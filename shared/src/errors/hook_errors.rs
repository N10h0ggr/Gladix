use thiserror::Error;

#[derive(Error, Debug)]
pub enum HookError {
    #[error("Unknown hook event processed: {event_type}")]
    UnknownEvent { event_type: String },
}
