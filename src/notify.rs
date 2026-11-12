use crate::proc::ElevationContext;
use notify_rust::{Notification, Timeout, Urgency};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationUrgency {
    Low,
    Normal,
    Critical,
}

impl From<NotificationUrgency> for Urgency {
    fn from(val: NotificationUrgency) -> Self {
        match val {
            NotificationUrgency::Low => Urgency::Low,
            NotificationUrgency::Normal => Urgency::Normal,
            NotificationUrgency::Critical => Urgency::Critical,
        }
    }
}

#[derive(Debug)]
pub enum NotifyError {
    DbusError(String),
}

impl fmt::Display for NotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NotifyError::DbusError(msg) => write!(f, "D-Bus notification error: {}", msg),
        }
    }
}

impl std::error::Error for NotifyError {}

/// Active notification that auto-closes on Drop.
pub struct ActiveNotification {
    handle: Option<notify_rust::NotificationHandle>,
}

impl ActiveNotification {
    pub fn new(handle: notify_rust::NotificationHandle) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    #[allow(dead_code)]
    pub fn id(&self) -> Option<u32> {
        self.handle.as_ref().map(|h| h.id())
    }

    pub fn close(&mut self) {
        if let Some(h) = self.handle.take() {
            h.close();
        }
    }
}

impl Drop for ActiveNotification {
    fn drop(&mut self) {
        self.close();
    }
}

/// Send a desktop notification alerting the user of privilege elevation.
pub fn send_elevation_notification(
    context: &ElevationContext,
) -> Result<ActiveNotification, NotifyError> {
    let summary = "Privilege Elevation Requested";
    let body = context.format_notification_body();

    let timeout = Timeout::Milliseconds(15_000);

    let handle = Notification::new()
        .appname("conduct")
        .summary(summary)
        .body(&body)
        .icon("dialog-password")
        .urgency(Urgency::Critical)
        .timeout(timeout)
        .show()
        .map_err(|e| NotifyError::DbusError(e.to_string()))?;

    Ok(ActiveNotification::new(handle))
}

/// Send a notification with custom fields.
pub fn send_notification(
    app_name: &str,
    summary: &str,
    body: &str,
    icon: &str,
    urgency: NotificationUrgency,
    timeout_ms: u32,
) -> Result<u32, NotifyError> {
    let timeout = if timeout_ms == 0 {
        Timeout::Never
    } else {
        Timeout::Milliseconds(timeout_ms)
    };

    let handle = Notification::new()
        .appname(app_name)
        .summary(summary)
        .body(body)
        .icon(icon)
        .urgency(urgency.into())
        .timeout(timeout)
        .show()
        .map_err(|e| NotifyError::DbusError(e.to_string()))?;

    Ok(handle.id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urgency_conversion() {
        assert_eq!(
            Urgency::from(NotificationUrgency::Critical),
            Urgency::Critical
        );
        assert_eq!(Urgency::from(NotificationUrgency::Normal), Urgency::Normal);
        assert_eq!(Urgency::from(NotificationUrgency::Low), Urgency::Low);
    }
}
