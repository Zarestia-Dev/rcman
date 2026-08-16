use rcman::SettingsSchema;
use rcman_derive::SettingsSchema;
use serde::{Deserialize, Serialize};

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
#[schema(category = "email")]
struct EmailAction {
    pub smtp_host: String,
    pub smtp_port: u16,
}

#[derive(SettingsSchema, Default, Serialize, Deserialize)]
#[schema(category = "webhook")]
struct WebhookAction {
    pub url: String,
}

#[derive(SettingsSchema, Serialize, Deserialize)]
#[serde(tag = "kind")]
enum Action {
    #[serde(rename = "email_action")]
    #[setting(label = "Send Email")]
    Email(EmailAction),
    #[serde(rename = "webhook_action")]
    #[setting(label = "Trigger Webhook")]
    Webhook(WebhookAction),
}

impl Default for Action {
    fn default() -> Self {
        Self::Email(EmailAction::default())
    }
}

fn main() {
    let metadata = Action::get_metadata();
    assert!(metadata.contains_key("kind"));
    assert!(metadata.contains_key("email.smtp_host"));
    assert!(metadata.contains_key("webhook.url"));

    assert_eq!(Action::EMAIL, "email_action");
    assert_eq!(Action::WEBHOOK, "webhook_action");
    assert_eq!(Action::ALL_KEYS, &[Action::EMAIL, Action::WEBHOOK]);
}
