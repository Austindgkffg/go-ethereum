// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/Clones.sol";

contract Factory {
    address public owner;
    address public receiver;
    address public sweeperImp; // The logic contract
    address public proxyImp;   // The shell contract (MinimalProxy)

    // Maps user address -> their specific proxy address
    mapping(address => address) public account_to_payment_address;
    
    // Maps token address -> is approved boolean
    mapping(address => bool) public isTokenApproved;

    constructor(
        address _owner, 
        address _receiver, 
        address _sweeperImp, 
        address _proxyImp
    ) {
        owner = _owner;
        receiver = _receiver;
        sweeperImp = _sweeperImp;
        proxyImp = _proxyImp;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function set_token_approvals(address[] memory tokens, bool status) public onlyOwner {
        for (uint i = 0; i < tokens.length; i++) {
            isTokenApproved[tokens[i]] = status;
        }
    }

    function create_payment_address() public returns (address) {
        require(account_to_payment_address[msg.sender] == address(0), "Address already exists");
        
        // Clone the 'proxyImp' which knows how to delegate to 'sweeperImp'
        address clone = Clones.clone(proxyImp);
        account_to_payment_address[msg.sender] = clone;
        
        return clone;
    }
}
