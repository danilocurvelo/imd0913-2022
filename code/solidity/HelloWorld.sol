pragma solidity ^0.5.0;

contract HelloWorld {
    
    string storedData;
    
    function set(string memory x) public {
        storedData = x;
    }
    
    function get() public view returns (string memory) {
        return storedData;
    }
    
}
