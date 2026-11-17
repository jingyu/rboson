use serde_cbor::Value;

use boson_api::Id;
use crate::internal::notification::Body;

fn body(tag: &str, payload: Option<Value>) -> Body {
    let mut map = [(
        Value::Text("e".into()),
        Value::Text(tag.into()),
    )]
    .into_iter()
    .collect::<std::collections::BTreeMap<_, _>>();
    if let Some(payload) = payload {
        map.insert(Value::Text("b".into()), payload);
    }
    serde_cbor::value::from_value(Value::Map(map)).expect("valid notification body")
}

fn id_value(id: &Id) -> Value {
    Value::Bytes(id.as_bytes().to_vec())
}

fn id_map(id: &Id, owner: &Id, session: &Id) -> Value {
    Value::Map([
        (Value::Text("id".into()), id_value(id)),
        (Value::Text("o".into()), id_value(owner)),
        (Value::Text("sid".into()), id_value(session)),
        (Value::Text("p".into()), Value::Integer(0)),
    ].into_iter().collect())
}

#[test]
fn test_notification() {
    let id = Id::random();
    let other = Id::random();
    let session = Id::random();

    let cases = vec![
        body("sn", Some(Value::Map([
            (Value::Text("id".into()), id_value(&other)),
            (Value::Text("o".into()), Value::Bool(true)),
            (Value::Text("lt".into()), Value::Integer(7)),
        ].into_iter().collect()))),
        body("cs", Some(Value::Map([
            (Value::Text("v".into()), Value::Integer(3)),
            (Value::Text("t".into()), Value::Integer(0)),
        ].into_iter().collect()))),
        body("cc", Some(id_map(&other, &id, &session))),
        body("cd", None),
        body("cj", Some(id_map(&other, &id, &session))),
        body("cl", None),
        body("cot", Some(id_value(&other))),
        body("csr", Some(Value::Bytes(vec![7; 64]))),
        body("ciu", Some(Value::Map(Default::default()))),
        body("cru", Some(Value::Map([
            (Value::Text("ids".into()), Value::Array(vec![id_value(&other)])),
            (Value::Text("r".into()), Value::Integer(0)),
        ].into_iter().collect()))),
        body("cmb", Some(Value::Array(vec![id_value(&other)]))),
        body("cmu", Some(Value::Array(vec![id_value(&other)]))),
        body("cmr", Some(Value::Array(vec![id_value(&other)]))),
        body("cmj", Some(Value::Map([
            (Value::Text("id".into()), id_value(&other)),
            (Value::Text("r".into()), Value::Integer(0)),
            (Value::Text("j".into()), Value::Integer(1)),
        ].into_iter().collect()))),
        body("cml", Some(id_value(&other))),
    ];

    for body in cases {
        let expected = format!("{:?}", body);

        let encoded = serde_cbor::to_vec(&body)
                .expect("notification body should serialize");
        let decoded: Body = serde_cbor::from_slice(&encoded)
                .expect("notification body should deserialize");

        assert_eq!(format!("{:?}", decoded), expected);
    }
}
