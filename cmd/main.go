Record what port this is set up on e.g port 3000

1. Create and connect to the Database and record all information to it  :
/Users/admin/Desktop/synthron_blockchain_final/cmd/database
/Users/admin/Desktop/synthron_blockchain_final/cmd/database/blockchain.db
log this 

2. Create all 3 genesis Wallets
/Users/admin/Desktop/synthron_blockchain_final/pkg/wallet/genesis_creator_wallet.go
/Users/admin/Desktop/synthron_blockchain_final/pkg/wallet/initial_company_development_wallet.go
/Users/admin/Desktop/synthron_blockchain_final/pkg/wallet/initial_internal_charity_wallet.go
log this

3. Create genesis Block and start intial distribution to the 
created wallet: /Users/admin/Desktop/synthron_blockchain_final/pkg/wallet/genesis_creator_wallet.go
log 

4. make sure all transactions are recording and logging 

5. use the implementation in this file of the type of nodes in the main.go
/Users/admin/Desktop/synthron_blockchain_final/cmd/node.go

6. connect peers and full network and firewall: /Users/admin/Desktop/synthron_blockchain_final/pkg/network

7. Set-up Security:/Users/admin/Desktop/synthron_blockchain_final/pkg/security

8. Connect Consensus: 
/Users/admin/Desktop/synthron_blockchain_final/pkg/consensus
/Users/admin/Desktop/synthron_blockchain_final/pkg/consensus/proof_of_stake
/Users/admin/Desktop/synthron_blockchain_final/pkg/consensus/proof_of_work
/Users/admin/Desktop/synthron_blockchain_final/pkg/consensus/synthron_coin

9. connect transaction stuff:
/Users/admin/Desktop/synthron_blockchain_final/pkg/transaction

10. connect in the wallet:
/Users/admin/Desktop/synthron_blockchain_final/pkg/wallet

11. connect in web3:
/Users/admin/Desktop/synthron_blockchain_final/pkg/web3


12. 


13. Connect in cross-chain
/Users/admin/Desktop/synthron_blockchain_final/pkg/cross-chain


14. add maintainance:
/Users/admin/Desktop/synthron_blockchain_final/pkg/maintainance

15. add the loanpool:
/Users/admin/Desktop/synthron_blockchain_final/pkg/loanpool

16. add security implementations: /Users/admin/Desktop/synthron_blockchain_final/pkg/security

17. add the use of smart contracts for the network to interact with it:
/Users/admin/Desktop/synthron_blockchain_final/pkg/smart_contracts


18. add all ecosystem use cases to it:
/Users/admin/Desktop/synthron_blockchain_final/cmd/ecosystem.go

19. add the ability for this to be shared between multiple peers and nodes to make a fully decentralized system.





func main() {
	router := mux.NewRouter()

	// Register all transaction routes
	apis.RegisterTransactionRoutes(router)

	// Start the server
	log.Fatal(http.ListenAndServe(":8080", router))
}