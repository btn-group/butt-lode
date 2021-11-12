use crate::msg::{ConfigResponse, HandleMsg, InitMsg, QueryMsg};
use crate::state::{config, config_read, State};
use cosmwasm_std::{
    to_binary, Api, Binary, Env, Extern, HandleResponse, HumanAddr, InitResponse, Querier,
    StdError, StdResult, Storage,
};

pub const RESPONSE_BLOCK_SIZE: usize = 1;

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let state = State {
        admin: env.message.sender,
        viewing_key: msg.viewing_key.clone(),
        withdrawal_allowed_from: msg.withdrawal_allowed_from,
    };

    config(&mut deps.storage).save(&state)?;

    Ok(InitResponse {
        messages: vec![],
        log: vec![],
    })
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    match msg {
        HandleMsg::ChangeAdmin { address, .. } => change_admin(deps, env, address),
    }
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&public_config(deps)?),
    }
}

fn change_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: HumanAddr,
) -> StdResult<HandleResponse> {
    let mut state = config_read(&deps.storage).load()?;
    // Ensure that admin is calling this
    if env.message.sender != state.admin {
        return Err(StdError::Unauthorized { backtrace: None });
    }

    state.admin = address;
    config(&mut deps.storage).save(&state)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: None,
    })
}

fn public_config<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
) -> StdResult<ConfigResponse> {
    let state = config_read(&deps.storage).load()?;
    Ok(ConfigResponse {
        admin: state.admin,
        withdrawal_allowed_from: state.withdrawal_allowed_from,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::from_binary;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage};
    pub const MOCK_ADMIN: &str = "admin";

    // === HELPERS ===
    fn init_helper() -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let env = mock_env(MOCK_ADMIN, &[]);
        let mut deps = mock_dependencies(20, &[]);
        let msg = InitMsg {
            viewing_key: "nannofromthegirlfromnowhereisathaidemon?".to_string(),
            withdrawal_allowed_from: 3,
        };
        (init(&mut deps, env.clone(), msg), deps)
    }

    #[test]
    fn test_change_admin() {
        let (init_result, mut deps) = init_helper();

        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::ChangeAdmin {
            address: HumanAddr("bob".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env(MOCK_ADMIN, &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let res = query(&deps, QueryMsg::Config {}).unwrap();
        let value: ConfigResponse = from_binary(&res).unwrap();
        assert_eq!(value.admin, HumanAddr("bob".to_string()));
    }

    #[test]
    fn test_public_config() {
        let (_init_result, deps) = init_helper();

        let res = query(&deps, QueryMsg::Config {}).unwrap();
        let value: ConfigResponse = from_binary(&res).unwrap();
        // Test response does not include viewing key.
        // Test that the desired fields are returned.
        assert_eq!(
            ConfigResponse {
                admin: HumanAddr::from(MOCK_ADMIN),
                withdrawal_allowed_from: 3
            },
            value
        );
    }
}
