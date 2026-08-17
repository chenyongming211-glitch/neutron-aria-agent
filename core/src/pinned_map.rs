use aya::maps::{MapData, MapError};

fn pin_missing(error: &MapError) -> bool {
    match error {
        MapError::SyscallError(syscall) => {
            syscall.io_error.kind() == std::io::ErrorKind::NotFound
        }
        MapError::PinError { error: pin_error, .. } => match pin_error {
            aya::pin::PinError::SyscallError(syscall) => {
                syscall.io_error.kind() == std::io::ErrorKind::NotFound
            }
            _ => false,
        },
        _ => false,
    }
}

fn classify_optional_pin_open<T, E>(
    map_name: &str,
    result: Result<T, E>,
    is_missing: impl FnOnce(&E) -> bool,
) -> Result<Option<T>, String>
where
    E: std::fmt::Debug,
{
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if is_missing(&error) => Ok(None),
        Err(error) => Err(format!("open {}: {:?}", map_name, error)),
    }
}

pub(crate) fn open_optional_pin(
    map_name: &str,
    path: &str,
) -> Result<Option<MapData>, String> {
    classify_optional_pin_open(map_name, MapData::from_pin(path), pin_missing)
}

pub(crate) fn require_map_operation<T, E>(
    operation: &str,
    result: Result<T, E>,
) -> Result<T, String>
where
    E: std::fmt::Debug,
{
    result.map_err(|error| format!("{}: {:?}", operation, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    enum FakeMapError {
        Missing,
        Permission,
        WrongType,
        Iteration,
    }

    #[test]
    fn map_authority_optional_open_treats_only_not_found_as_absent() {
        assert_eq!(
            classify_optional_pin_open("QOS_CONFIG", Ok::<_, FakeMapError>(7), |_| false),
            Ok(Some(7))
        );
        assert_eq!(
            classify_optional_pin_open(
                "QOS_CONFIG",
                Err::<u8, _>(FakeMapError::Missing),
                |error| matches!(error, FakeMapError::Missing),
            ),
            Ok(None)
        );

        let error = classify_optional_pin_open(
            "QOS_CONFIG",
            Err::<u8, _>(FakeMapError::Permission),
            |error| matches!(error, FakeMapError::Missing),
        )
        .unwrap_err();
        assert!(error.contains("open QOS_CONFIG"));
        assert!(error.contains("Permission"));
    }

    #[test]
    fn map_authority_conversion_and_iteration_faults_are_errors() {
        let conversion = require_map_operation::<(), _>(
            "convert CT_TABLE_V4",
            Err(FakeMapError::WrongType),
        )
        .unwrap_err();
        assert!(conversion.contains("convert CT_TABLE_V4"));
        assert!(conversion.contains("WrongType"));

        let iteration = require_map_operation::<(), _>(
            "iterate CT_TABLE_V6",
            Err(FakeMapError::Iteration),
        )
        .unwrap_err();
        assert!(iteration.contains("iterate CT_TABLE_V6"));
        assert!(iteration.contains("Iteration"));
    }
}
