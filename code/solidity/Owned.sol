pragma solidity ^ 0.5.0;

contract Owned {
    
    address payable owner;
    
    constructor() public {
        owner = msg.sender;
    }
    
    modifier onlyOwner {
        require(msg.sender == owner, "Somente o dono do contrato pode executar essa funcao!");
        _;
    }
    
}

contract Mortal is Owned {
    function destroy() public onlyOwner {
        selfdestruct(owner);
    }
}
