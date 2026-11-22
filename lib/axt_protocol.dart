/// The Dart library of AXT (Avro eXchange Transfer).
///
/// AXT is the open standard of https://github.com/paxel/axt for small apps to
/// exchange typed records.
library;

export 'src/errors.dart' show AxtException, ErrorCode;
export 'src/file_reader.dart' show FileRecordResult;
export 'src/node.dart'
    show
        AxtNode,
        AxtStore,
        FilePreview,
        FileResult,
        OutgoingRecord,
        RecordChange,
        newRecordId;
export 'src/type_description.dart' show TypeDescription;
export 'src/records.dart'
    show DeleteWithLocalChanges, LocalChanges, Outcome, RecordPolicy;

/// The version of the AXT specification this library conforms to.
const String axtVersion = '0.2.0';
