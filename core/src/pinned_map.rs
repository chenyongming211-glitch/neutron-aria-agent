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
