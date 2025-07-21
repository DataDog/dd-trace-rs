use std::collections::HashMap;

use aws_sdk_sqs::types::MessageAttributeValue;

#[derive(Debug)]
pub struct SqsPropagator {}

impl aws_sdk_sqs::config::Intercept for SqsPropagator {
    fn modify_before_serialization(
        &self,
        context: &mut aws_sdk_sqs::config::interceptors::BeforeSerializationInterceptorContextMut<
            '_,
        >,
        _runtime_components: &aws_sdk_sqs::config::RuntimeComponents,
        _cfg: &mut aws_sdk_sqs::config::ConfigBag,
    ) -> Result<(), aws_sdk_sqs::error::BoxError> {
        let Some(input) = context
            .input_mut()
            .downcast_mut::<aws_sdk_sqs::operation::send_message::SendMessageInput>()
        else {
            return Ok(());
        };
        let mut distributed_context = HashMap::new();
        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject(&mut distributed_context);
        });
        let Ok(distributed_context) = serde_json::to_string(&distributed_context) else {
            // TODO: log warning here
            return Ok(());
        };
        let Ok(message_attribute_value) = MessageAttributeValue::builder()
            .data_type("String")
            .string_value(distributed_context)
            .build()
        else {
            return Ok(());
        };
        input
            .message_attributes
            .get_or_insert_default()
            .insert("_datadog".to_owned(), message_attribute_value);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SqsPropagator"
    }
}
