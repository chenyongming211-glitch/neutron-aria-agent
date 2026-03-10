# eBPF Firewall Design Deviation Fix Implementation Plan

> **For Claude:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix three critical design deviations from the "Identity-based TSS with Nested Bitmap" architecture.

**Architecture:** 
- Bitmap pool: Use ArrayOfMaps (outer) with nested Array<u8> (inner) for O(1) port filtering
- User-space: Implement LPM insertion, bitmap creation, and map pinning for persistence
- Policy lookup: Use bitmap_idx to index into outer array, then lookup port in inner map

**Tech Stack:** Rust + aya 0.13.1 (user-space), aya-ebpf 0.1.1 (kernel)

---

## Summary of Changes

### 1. eBPF Maps (maps.rs)
- Changed PORT_BITMAP_POOL from `HashMap<PortBitmapKey, u8>` to `ArrayOfMaps<u32, u32>`
- Removed unused PortBitmapKey struct
- Outer array size: 1024 (supports 1024 policy groups)
- Inner maps: Created dynamically in user-space (Array<u8> with 65536 entries per port)

### 2. eBPF Policy Application (main.rs)
- Updated apply_policy() to use nested bitmap lookup:
  - Get inner map using bitmap_idx
  - Lookup port in inner map
  - Return action (0=PASS, 1=DROP)

### 3. User-Space Manager (manager.rs) - TODO
- Add LPM network insertion (src/dst IP -> id mapping)
- Add bitmap creation (create inner Array maps, populate port actions)
- Add map pinning for persistence across process restarts
- Fix CLI to reuse pinned maps instead of reloading

---

## Tasks

### Task 1: Fix eBPF PORT_BITMAP_POOL Map Type ✅ COMPLETED

**Files modified:**
- `ebpf/src/maps.rs:21-22`

**Change:** 
```rust
// Before:
pub static PORT_BITMAP_POOL: HashMap<PortBitmapKey, u8> = HashMap::with_max_entries(65536 * 16, 0);

// After:
pub static PORT_BITMAP_POOL: ArrayOfMaps<u32, u32> = ArrayOfMaps::with_max_entries(1024, 0);
```

**Result:** Removed PortBitmapKey struct, now uses nested ArrayOfMaps

---

### Task 2: Fix eBPF apply_policy Function ✅ COMPLETED

**Files modified:**
- `ebpf/src/main.rs:97-115`

**Change:** Updated to use nested bitmap lookup
```rust
fn apply_policy(policy: &PolicyValue, dst_port: u16) -> u32 {
    if policy.has_port_filter == 0 {
        return if policy.action == 0 { XDP_PASS } else { XDP_DROP };
    }

    let bitmap_idx = policy.bitmap_idx;
    let inner_map = match unsafe { PORT_BITMAP_POOL.get(&bitmap_idx) } {
        Some(m) => m,
        None => return XDP_PASS,
    };

    let port_key = dst_port as u32;
    let action = inner_map.get(&port_key).copied();

    match action {
        Some(a) => if a == 0 { XDP_PASS } else { XDP_DROP },
        None => XDP_PASS,
    }
}
```

---

### Task 3: Update User-Space Manager (In Progress)

**Files to modify:**
- `user/src/manager.rs`

**Required changes:**

1. **Add LPM insertion** - Insert IP subnet -> id mapping into SRC_IPV4_TRIE or DST_IPV4_TRIE

2. **Add bitmap creation** - Create inner Array maps and populate with port actions:
   - Create new Array<u8> with 65536 entries
   - Fill with default action (0 = pass)
   - Set specific port actions (1 = drop)
   - Get fd and store in PORT_BITMAP_POOL at bitmap_idx

3. **Add map pinning** - Pin maps to filesystem for persistence:
   - Use `bpf_pin()` or `Ebpf::pin()` on first load
   - Use `Ebpf::from_pin()` on subsequent runs

4. **Fix CLI reuse** - Don't reload eBPF on every command, reuse pinned maps
