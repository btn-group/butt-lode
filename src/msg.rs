use crate::state::SecretContract;
use cosmwasm_std::{HumanAddr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub receivable_address: Option<HumanAddr>,
    pub time_delay: u64,
    pub viewing_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    ChangeAdmin {},
    NominateNewAdmin {
        address: Option<HumanAddr>,
    },
    SendToken {
        amount: Uint128,
        token: SecretContract,
    },
    SetViewingKeyForSnip20 {
        token: SecretContract,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Config {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ConfigResponse {
    pub admin: HumanAddr,
    pub admin_change_allowed_from: u64,
    pub new_admin_nomination: Option<HumanAddr>,
    pub receivable_address: Option<HumanAddr>,
    pub viewing_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveMsg {
    Deposit {},
}
