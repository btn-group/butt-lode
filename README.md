# BUTT lode
***lode*** - an abundant store

Secret network smart contract that allows admin to transfer tokens to an allocated address.
It has a time delay for changing the receivable address and admin.

## Concept
* BUTT from other contracts (fees, payments etc) are sent here.
* Admin can transfer tokens from this contract to the designated receivable contract.
* Admin can nominate a new admin. After 5 days, the nominated address can accept the nomination.
* Admin can nominate a new receivable address. After 5 days, admin can change the receivable address to the nominated address.

## Testing locally examples
```
# Run chain locally
docker run -it --rm -p 26657:26657 -p 26656:26656 -p 1337:1337 -v $(pwd):/root/code --name secretdev enigmampc/secret-network-sw-dev

# Access container via separate terminal window 
docker exec -it secretdev /bin/bash

# cd into code folder
cd code

# Store contracts required for test
secretcli tx compute store buttcoin.wasm.gz --from a --gas 3000000 -y --keyring-backend test
secretcli tx compute store snip-20-reference-impl.wasm.gz --from a --gas 3000000 -y --keyring-backend test
secretcli tx compute store profit-distributor-b.wasm.gz --from a --gas 3000000 -y --keyring-backend test
secretcli tx compute store butt-lode.wasm.gz --from a --gas 3000000 -y --keyring-backend test

# Get the contract's id
secretcli query compute list-code

# Init Buttcoin 
CODE_ID=1
INIT='{"name": "Buttcoin", "symbol": "BUTT", "decimals": 6, "initial_balances": [{"address": "secret1qwkd2mdr0w79fyz6zyljs7u3cnff6dtekp3y39", "amount": "1000000000000000000"},{"address": "secret1wz95rde3wrf9e4hvdtwgey4d9zeys35sevchg5", "amount": "1000000000000000000"}], "prng_seed": "testing"}'
secretcli tx compute instantiate $CODE_ID "$INIT" --from a --label "Buttcoin" -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

# Set viewing key for Buttcoin
secretcli tx compute execute secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg '{"set_viewing_key": { "key": "testing" }}' --from a -y --keyring-backend test
secretcli tx compute execute secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg '{"set_viewing_key": { "key": "testing" }}' --from b -y --keyring-backend test

# Init stake token
CODE_ID=2
INIT='{"name": "Secret Finance", "symbol": "SEFI", "decimals": 6, "prng_seed": "testing", "config": {"enable_burn": true, "enable_mint": true, "public_total_supply": true}}'
secretcli tx compute instantiate $CODE_ID "$INIT" --from a --label "sefi" -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

# Mint SEFI to users
secretcli tx compute execute secret10pyejy66429refv3g35g2t7am0was7ya6hvrzf '{ "mint": { "recipient": "secret1qwkd2mdr0w79fyz6zyljs7u3cnff6dtekp3y39", "amount": "1000000000000000000" } }' --from a -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt
secretcli tx compute execute secret10pyejy66429refv3g35g2t7am0was7ya6hvrzf '{ "mint": { "recipient": "secret1wz95rde3wrf9e4hvdtwgey4d9zeys35sevchg5", "amount": "1000000000000000000" } }' --from a -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

# Set viewing key for SEFI
secretcli tx compute execute secret10pyejy66429refv3g35g2t7am0was7ya6hvrzf '{"set_viewing_key": { "key": "testing" }}' --from a -y --keyring-backend test
secretcli tx compute execute secret10pyejy66429refv3g35g2t7am0was7ya6hvrzf '{"set_viewing_key": { "key": "testing" }}' --from b -y --keyring-backend test

# Init profit distributor B
CODE_ID=3
INIT='{"incentivized_token": {"address": "secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg", "contract_hash": "4CD7F64B9ADE65200E595216265932A0C7689C4804BE7B4A5F8CEBED250BF7EA"}, "profit_token": {"address": "secret10pyejy66429refv3g35g2t7am0was7ya6hvrzf", "contract_hash": "35F5DB2BC5CD56815D10C7A567D6827BECCB8EAF45BC3FA016930C4A8209EA69"}, "viewing_key": "DoTheRightThing."}'
secretcli tx compute instantiate $CODE_ID "$INIT" --from a --label "profit-distributor-b" -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

# Init BUTT lode
CODE_ID=4
INIT='{"time_delay": 432000, "viewing_key": "DoTheRightThing."}'
secretcli tx compute instantiate $CODE_ID "$INIT" --from a --label "butt-lode" -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

# Init address alias
CODE_ID=5
INIT='{"buttcoin": {"address": "secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg", "contract_hash": "4CD7F64B9ADE65200E595216265932A0C7689C4804BE7B4A5F8CEBED250BF7EA"}, "butt_lode": {"address": "secret1xzlgeyuuyqje79ma6vllregprkmgwgavk8y798", "contract_hash": "C924D1D07B2386BDBDC0F0F324F551EBEB1C09D628C5047B9E8FA61C17FCC423"}, "aliases": [{"alias": "bogoggl", "address": "secret1pe5c78vprahdqlwwx7rlz74rtnxhp8swgrtacr"}, {"alias": "sex", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1626422552/secret_network/address_alias/user_uploads/rso5ouuglk3tq5itkayd.jpg", "address": "secret1hdam2af5gpytmw3lfkhlnqjapqd9fh3skusd6z"}, {"alias": "secretnetwork", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1626421705/secret_network/address_alias/user_uploads/irict0nfewkvoikpbajd.jpg", "address": "secret1s2g7fepnl2hq65gflpv92legke452nnzuqtcet"}, {"alias": "x", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1626421288/secret_network/address_alias/user_uploads/dxh13oasotliwggbczst.jpg", "address": "secret1c4ustsk77j7tljdnee2ehm2jxkn22666y5sa25"}, {"alias": "xxx", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1626419086/secret_network/address_alias/user_uploads/pyqac3nll9escxjzwp1a.gif", "address": "secret1u2x7ndzsau7e9n5xu4ng2hghxp58q5xg8hevkk"}, {"alias": "etoque angry dawg", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1623854847/secret_network/address_alias/user_uploads/k0pkom4sarf6av6uvgmg.png", "address": "secret13yfwh0lv3f7c703etpwm6pjdp2jyuwfk527g7j"}, {"alias": "gus", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1623854331/secret_network/address_alias/user_uploads/ytiylm9s4q5z6dik8kx1.jpg", "address": "secret1nu5j6lqpaw47qqs9d6ym835ywyn462l4gq723n"}, {"alias": "btn.group admin3", "avatar_url": "https://res.cloudinary.com/hv5cxagki/image/upload/secret_network/yield_optimizer/3143e566-c3f1-4252-80f2-6bbbc5242368_pfkrls.png", "address": "secret1wgfe52tz8hthe236nh28y0qac4df9yg2qdmrpr"}, {"alias": "btn.group admin2", "avatar_url": "https://res.cloudinary.com/hv5cxagki/image/upload/v1/secret_network/smart_contract_interface/contract_rough_MG_tw1vei.png", "address": "secret1s32ccax83w483rj5nsnsz56wvryfszrhev7sjn"}, {"alias": "petar", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1623188805/secret_network/address_alias/user_uploads/muvb0mnrflvjd79pgcoq.png", "address": "secret1yza5mzgmypm43mzzgwyg3nt958vchxracj3mx3"}, {"alias": "cryptochrisb", "address": "secret1fu9kr29n7d0k59dtezkl09pz8rwazykf6yctp0"}, {"alias": "emily chen", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1622768025/secret_network/address_alias/user_uploads/mkiq3e1erohtph51vs9b.png", "address": "secret1sm7yp4gw22xawvekjcvt06wenz22mfspukwfks"}, {"alias": "patrick", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1622663448/secret_network/address_alias/user_uploads/ggkqrbqmchoa9olbyk6v.png", "address": "secret1j486ekz7ksn4l7s2tlnnh9mexrex3nxz7ue80u"}, {"alias": "joe", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1622651509/secret_network/address_alias/user_uploads/ybkikya8ozpmvvykc7di.jpg", "address": "secret1sv83nqu9lql67lz8dvumerz5zm9xlnsq9xpxjx"}, {"alias": "s", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1622640201/secret_network/address_alias/user_uploads/y6nitqlx5u5plj6e6s5e.jpg", "address": "secret1ctqpkfjfhtl8vhz52rmf39gzcdfpamftr9h2yh"}, {"alias": "syck", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1622639791/secret_network/address_alias/user_uploads/ajizdbadebzgizjzn3st.jpg", "address": "secret1x2nr7lx0dgguuadz9k93zjf2gt8elvnsjhyq9s"}, {"alias": "this is not fine!!", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1622617116/secret_network/address_alias/user_uploads/myvj4h8sy7u5vmqpabih.jpg", "address": "secret146uuuagufhk64k6feckcuef2hxvsg4cneyn40k"}, {"alias": "btn.group admin", "avatar_url": "http://res.cloudinary.com/hv5cxagki/image/upload/v1622605639/secret_network/address_alias/user_uploads/dd07sfnuj1tnwe5nrfzg.png", "address": "secret1zm55tcme6epjl4jt30v05gh9xetyp9e3vvv6nr"}]}'
secretcli tx compute instantiate $CODE_ID "$INIT" --from a --label "address alias - btn.group" -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

# Query config for butt lode
secretcli query compute query secret1xzlgeyuuyqje79ma6vllregprkmgwgavk8y798 '{"config": {}}'

# Query that BUTT was sent to BUTT lode
secretcli tx compute execute secret1xzlgeyuuyqje79ma6vllregprkmgwgavk8y798 '{"set_viewing_key_for_snip20": {"token": {"address": "secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg", "contract_hash": "4CD7F64B9ADE65200E595216265932A0C7689C4804BE7B4A5F8CEBED250BF7EA"}}}' --from a -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt
secretcli query compute query secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg '{"balance": {"address": "secret1xzlgeyuuyqje79ma6vllregprkmgwgavk8y798", "key": "DoTheRightThing."}}'

# Nominate new admin
secretcli tx compute execute secret1xzlgeyuuyqje79ma6vllregprkmgwgavk8y798 '{"nominate_new_admin": {"address": "secret1wz95rde3wrf9e4hvdtwgey4d9zeys35sevchg5"}}' --from a -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

# Change admin
secretcli tx compute execute secret1xzlgeyuuyqje79ma6vllregprkmgwgavk8y798 '{"change_admin": {}}' --from b -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

# Nominate new receivable address
secretcli tx compute execute secret1xzlgeyuuyqje79ma6vllregprkmgwgavk8y798 '{"nominate_new_receivable_address": {"address": "secret1sh36qn08g4cqg685cfzmyxqv2952q6r8vqktuh"}}' --from b -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

# Chance receivable address
secretcli tx compute execute secret1xzlgeyuuyqje79ma6vllregprkmgwgavk8y798 '{"change_receivable_address": {}}' --from b -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt

# Send token to receivable address
secretcli tx compute execute secret1xzlgeyuuyqje79ma6vllregprkmgwgavk8y798 '{"send_token": {"amount": "1000000", "token": {"address": "secret18vd8fpwxzck93qlwghaj6arh4p7c5n8978vsyg", "contract_hash": "4CD7F64B9ADE65200E595216265932A0C7689C4804BE7B4A5F8CEBED250BF7EA"}}}' --from b -y --keyring-backend test --gas 3000000 --gas-prices=3.0uscrt
```

## References
1. BUTT lode: https://btn.group/secret_network/butt_lode
2. Secret contracts guide: https://github.com/enigmampc/secret-contracts-guide
