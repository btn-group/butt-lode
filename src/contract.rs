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
        admin_change_allowed_from: u64::MAX,
        new_admin_nomination: None,
        viewing_key: msg.viewing_key,
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
        HandleMsg::ChangeAdmin {} => change_admin(deps, env),
        HandleMsg::NominateNewAdmin { address } => nominate_new_admin(deps, env, address),
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
) -> StdResult<HandleResponse> {
    let mut state = config_read(&deps.storage).load()?;
    // Ensure that nominated new admin is calling this
    if state.new_admin_nomination.is_some() {
        if env.message.sender == state.new_admin_nomination.clone().unwrap() {
            if env.block.time > state.admin_change_allowed_from {
                state.admin = env.message.sender;
                config(&mut deps.storage).save(&state)?;
            } else {
                return Err(StdError::generic_err(format!(
                    "Current time: {}. Admin change allowed from: {}.",
                    env.block.time, state.admin_change_allowed_from
                )));
            }
        } else {
            return Err(StdError::Unauthorized { backtrace: None });
        }
    } else {
        return Err(StdError::generic_err(format!("No new admin nomination.")));
    }

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: None,
    })
}

fn nominate_new_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: Option<HumanAddr>,
) -> StdResult<HandleResponse> {
    let mut state = config_read(&deps.storage).load()?;
    // Ensure that admin is calling this
    if env.message.sender != state.admin {
        return Err(StdError::Unauthorized { backtrace: None });
    }

    state.new_admin_nomination = address;
    state.admin_change_allowed_from = env.block.time + 432_000;
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
        admin_change_allowed_from: state.admin_change_allowed_from,
        new_admin_nomination: state.new_admin_nomination,
        viewing_key: state.viewing_key,
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

    fn mock_user_address() -> HumanAddr {
        HumanAddr::from("bob")
    }

    #[test]
    fn test_change_admin() {
        let (_init_result, mut deps) = init_helper();

        // when there is no nominated new admin
        // * it raises an error
        let change_admin_msg = HandleMsg::ChangeAdmin {};
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            change_admin_msg.clone(),
        );
        assert_eq!(
            handle_result.unwrap_err(),
            StdError::generic_err(format!("No new admin nomination."))
        );

        // when there is a nominated admin
        let handle_msg = HandleMsg::NominateNewAdmin {
            address: Some(mock_user_address()),
        };
        handle(&mut deps, mock_env(MOCK_ADMIN, &[]), handle_msg.clone()).unwrap();

        // = when change of admin is called by the person who is not nominated
        // = * it raises an error
        let handle_result = handle(
            &mut deps,
            mock_env(MOCK_ADMIN, &[]),
            change_admin_msg.clone(),
        );
        assert_eq!(
            handle_result.unwrap_err(),
            StdError::Unauthorized { backtrace: None }
        );

        // = when change of admin is called by the person who is nominated
        // == when it is not time to call the change of admin
        // == * it raises an error
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            change_admin_msg.clone(),
        );
        assert_eq!(
            handle_result.unwrap_err(),
            StdError::generic_err(format!(
                "Current time: {}. Admin change allowed from: {}.",
                1571797419,
                1571797419 + 60 * 60 * 24 * 5
            ))
        );

        // == when it is time to call the change of admin
        let mut state = config_read(&deps.storage).load().unwrap();
        state.admin_change_allowed_from = 1571797419 - 1;
        config(&mut deps.storage).save(&state).unwrap();
        // == * it changes the admin
        handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            change_admin_msg,
        )
        .unwrap();
        let state = config_read(&deps.storage).load().unwrap();
        assert_eq!(state.admin, mock_user_address());
    }

    #[test]
    fn test_nominate_new_admin() {
        let (_init_result, mut deps) = init_helper();
        let handle_msg = HandleMsg::NominateNewAdmin {
            address: Some(mock_user_address()),
        };

        // when nomination is made by a non-admin
        let handle_result = handle(
            &mut deps,
            mock_env(mock_user_address(), &[]),
            handle_msg.clone(),
        );
        assert_eq!(
            handle_result.unwrap_err(),
            StdError::Unauthorized { backtrace: None }
        );

        // when nomination is made by an admin
        let handle_result = handle(&mut deps, mock_env(MOCK_ADMIN, &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let res = query(&deps, QueryMsg::Config {}).unwrap();
        let value: ConfigResponse = from_binary(&res).unwrap();
        assert_eq!(value.new_admin_nomination, Some(mock_user_address()));
        assert_eq!(
            value.admin_change_allowed_from,
            mock_env(MOCK_ADMIN, &[]).block.time + (60 * 60 * 24 * 5)
        );
    }

    #[test]
    fn test_public_config() {
        let (_init_result, deps) = init_helper();
        let res = query(&deps, QueryMsg::Config {}).unwrap();
        let value: ConfigResponse = from_binary(&res).unwrap();
        assert_eq!(
            ConfigResponse {
                admin: HumanAddr::from(MOCK_ADMIN),
                admin_change_allowed_from: u64::MAX,
                new_admin_nomination: None,
                viewing_key: "nannofromthegirlfromnowhereisathaidemon?".to_string(),
                withdrawal_allowed_from: 3,
            },
            value
        );
    }
}
