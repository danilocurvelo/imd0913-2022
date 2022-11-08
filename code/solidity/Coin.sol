pragma solidity ^0.7.0;

contract Coin {
    
    address public minter; // dono do contrato
    mapping (address => uint) public balances;
    
    event Transferencia(address from, address to, uint amount);
    
    constructor() {
        minter = msg.sender;
    }
    
    function mint(address receiver, uint amount) public {
        require(msg.sender == minter);
        balances[receiver] += amount;
    }
    
    function send(address receiver, uint amount) public {
        require(amount <= balances[msg.sender], "Saldo insuficiente.");
        
        balances[msg.sender] -= amount;
        balances[receiver] += amount;
        emit Transferencia(msg.sender, receiver, amount);
    }
    
}
