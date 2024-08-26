use serde::Deserialize;

#[derive(Debug, Deserialize)]
/// Represents a legacy user.
pub struct UserLegacy {
    /// The number of followers.
    pub followers_count: u32,
    /// The screen name.
    pub screen_name: String,
    /// The number of statuses.
    pub statuses_count: u32,
}

/// Represents the result of a user.
#[derive(Debug, Deserialize)]
pub struct UserResult {
    /// The legacy user.
    pub legacy: UserLegacy,
}

/// Represents user data.
#[derive(Debug, Deserialize)]
pub struct UserData {
    /// The user result.
    pub result: UserResult,
}

/// Represents data.
#[derive(Debug, Deserialize)]
pub struct Data {
    /// The user data.
    pub user: UserData,
}

#[derive(Debug, Deserialize)]
/// Represents a user identified by their screen name.
pub struct UserByScreenName {
    /// The data
    pub data: Data,
}