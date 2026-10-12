# DAO.solid - Decentralized Authoritative Organisation Contract Template

## Overview
A Solidity-like smart contract template for launching Decentralized Authoritative Organisations (DAOs) on the Oxydome blockchain. Each DAO has its own wallet address and can act as an individual blockchain user.

## Contract Features

### DAO Identity
- `dao_address` - The DAO's own address on Oxydome (`address(this)`)
- Acts as an individual blockchain user with its own identity

### Member Role System
- **Role Enum**: `Admin`, `Member`, `Observer`
- `mapping(address => Role) public members` - Tracks member roles
- `add_member(address _new_member, Role _role)` - Admin-only function to add members
- `remove_member(address _old_member)` - Admin-only function to remove members
- `get_role(address _member)` - View a member's role

### Proposal Voting System
- **Struct Proposal**: Contains description, voting period, vote counts, execution status
- `propose(bytes32 _description, uint256 _voting_period)` - Create a new proposal
- `vote(uint256 _proposal_id, bool _support)` - Cast a vote (yes/no)
- `execute(uint256 _proposal_id)` - Admin-only execution after voting period ends
- **Quorum checking**: Requires minimum participation percentage
- **Simple majority**: Yes votes must exceed No votes for execution

### Treasury Functions
- `deposit()` - Payable function to add funds to DAO treasury
- `withdraw(uint256 _amount)` - Admin-only fund withdrawal
- `get_balance()` - Returns treasury balance (`address(this).balance`)
- `propose_payment(address _to, uint256 _amount, bytes32 _description)` - Propose a treasury payment

### Member Management
- Only admins can add/remove members
- `get_role(address _member)` - View a member's role
- Role hierarchy: `Admin > Member > Observer`

### Events
| Event | Parameters | Description |
|-------|-----------|-------------|
| `MemberAdded` | `address indexed member, Role role` | Emitted when a new member is added |
| `MemberRemoved` | `address indexed member` | Emitted when a member is removed |
| `ProposalCreated` | `uint256 indexed proposal_id, address indexed proposer, string description` | Emitted when a new proposal is created |
| `VoteCast` | `uint256 indexed proposal_id, indexed voter, bool support` | Emitted when someone votes on a proposal |
| `ProposalExecuted` | `uint256 indexed proposal_id` | Emitted when a proposal is successfully executed |
| `PaymentExecuted` | `uint256 indexed proposal_id, indexed to, uint256 amount` | Emitted when a treasury payment is executed |

### Constructor
```solidity
constructor() {
    dao_address = address(this);
}
```

### Usage Example

```solidity
// Deploy a new DAO
solidc deploy DAO.solid --initial-admin 0xadmin_address

// Add members
DAO.add_member(0xmember1, Role.Member);
DAO.add_member(0xadmin2, Role.Admin);

// Create proposals
DAO.propose("Fund new project", 86400); // 1 day voting period
DAO.vote(0, true); // Vote yes on proposal 0
DAO.execute(0); // Execute if quorum and majority reached
```

### Files
- `crates/solid/templates/DAO.solid` - The full contract source

## Technical Details

- **Compiler**: `cargo build -p oxydome-solid`
- **Tests**: `cargo test --workspace` (all pass, no regressions)
- **File format**: `.solid` - Solid language source format
- **Events**: 6 events for comprehensive state change tracking
- **Modifiers**: `only admin` checks on sensitive operations
- **State variables**: Carefully scoped to prevent unauthorized access

## Deployment

1. Compile: `solidc compile DAO.solid -o build/DAO.ovm`
2. Deploy: `oxydome-cli deploy build/DAO.ovm --initial-admin <admin_address>`
3. The DAO is now active with its own wallet address

---

*Generated from crates/solid/templates/DAO.solid*
