# BUTT lode
***lode*** - an abundant store

Secret network smart contract that allows admin to transfer tokens to an allocated address.
It has a time delay for changing the receivable address and admin.

## Concept
* BUTT from other contracts (fees, payments etc) are sent here.
* Admin can transfer tokens from this contract to the designated receivable contract.
* Admin can nominate a new admin. After 5 days, the nominated address can accept the nomination.
* Admin can nominate a new receivable address. After 5 days, admin can change the receivable address to the nominated address.
