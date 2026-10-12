# Token.solid - Fungible Token Contract Template

## Overview
A fungible token contract for the Oxydome blockchain, bound by the same rules as Ox currency. Only creatable by DAO contracts, with each DAO able to have exactly 1 Token to manage.

## Contract Features

### Token Identity
- **name**: Token name (e.g., "Oxydome Coin")
- **symbol**: Token symbol (e.g., "OXD")
- **decimal_places**: Number of divisibility units (standard: 18)
- **dao_creator**: The DAO address that created this token
- **dao_has_token**: Flag enforcing 1 token per DAO

### Supply Rules (Ox Currency Compatible)
- **total_supply**: Total token supply in existence
- **max_supply**: Maximum supply cap (0 = unlimited, set at creation)
- **balances**: `mapping(address => uint256)` - per-address balance tracking
- **allowance**: `mapping(address => mapping(address => uint256))` - spender allowance tracking

### Creation Restriction
- **Only DAOs can create tokens**: The `only_dao_creator` modifier validates `msg.sender == dao_creator`
- **1 Token per DAO**: `dao_has_token` mapping - if a DAO already has a token, creating another reverts
- Constructor takes: `name`, `symbol`, `decimals` (1-18 range)

### Mint Function
- `mint(address _to, uint256 _value)` - DAO-restricted
- Increases `total_supply` and `_to`'s balance
- Enforces `max_supply` cap (reverts if exceeded)
- Cannot mint to zero address
- Emits `Mint` and `Transfer` events (from 0x0 to recipient)

### Transfer Function
- `transfer(address _to, uint256 _value)` - Standard transfer
- Validates: `_to != address(0)`, `_value > 0`, sender has sufficient balance
- Updates `balances[msg.sender] -= _value` and `balances[_to] += _value`
- Emits `Transfer` event: `msg.sender` → `_to`

### Allowance / `transfer_from`
- `transfer_from(address _from, address _to, uint256 _value)`
- Validates `_from != address(0)`, `_to != address(0)`, `_value > 0`
- Checks `allowance[_from][msg.sender] >= _value`
- Updates allowance, balances, emits `Transfer` event

### Pausable Functionality
- `paused` boolean flag
- `when_not_paused` modifier reverts if paused
- `toggle_pause()` - DAO-restricted function to pause/unpause
- `get_total_supply()`, `balance_of()`, `get_name()`, `get_symbol()`, `get_decimals()` - view functions

### Restrictions (Ox Currency Rules)
1. **Supply Cap**: `total_supply` must never exceed `max_supply`
2. **Transfer Limitations**: 
   - Cannot transfer negative amounts
   - Cannot transfer more than balance
   - Cannot transfer to zero address
3. **Balance Checks**: Sender must have sufficient balance
4. **Zero Address Rejection**: Transfer to 0x0 must revert
5. **Decimal Precision**: value / 10^decimal_places must be integer for transfers

### Events
| Event | Parameters | Description |
|-------|-----------|-------------|
| `Transfer` | `address indexed from, address indexed to, uint256 value` | Token transfer between addresses |
| `Mint` | `address indexed to, uint256 value` | New tokens created |
| `Creation` | `address indexed dao, string token_name, string token_symbol` | Token created by DAO |
| `PauseToggle` | `bool paused` | Pause state change |

### Getter Functions
- `get_total_supply()` → `uint256` - Total token supply
- `balance_of(address _owner)` → `uint256` - Address balance
- `get_name()` → `string memory` - Token name
- `get_symbol()` → `string memory` - Token symbol
- `get_decimals()` → `uint8` - Decimal places
- `dao_has_token_has()` → `bool` - Whether DAO has a token

### Constructor
```solidity
constructor(string memory _name, string memory _symbol, uint8 _decimals) {
    require(_decimals > 0, "Decimals must be > 0");
    require(_decimals <= 18, "Decimals must be <= 18");
    name = _name;
    symbol = _symbol;
    decimal_places = _decimals;
    total_supply = 0;
    max_supply = 0; // 0 = unlimited by default
    dao_creator = msg.sender;
    emit Creation(msg.sender, name, symbol);
}
```

### Mint Function
```solidity
function mint(address _to, uint256 _value) only_dao_creator external {
    if (max_supply > 0 && total_supply + _value > max_supply) {
        revert("Supply cap exceeded");
    }
    require(_to != address(0), "Cannot mint to zero address");
    total_supply += _value;
    balances[_to] += _value;
    emit Mint(_to, _value);
    emit Transfer(address(0), _to, _value);
}
```

### Transfer Function
```solidity
function transfer(address _to, uint256 _value) external {
    require(_to != address(0), "Cannot transfer to zero address");
    require(_value > 0, "Transfer amount must be > 0");
    require(balances[msg.sender] >= _value, "Insufficient balance");
    balances[msg.sender] -= _value;
    balances[_to] += _value;
    emit Transfer(msg.sender, _to, _value);
}
```

### `transfer_from` Function
```solidity
function transfer_from(address _from, address _to, uint256 _value) external {
    require(_from != address(0), "Cannot transfer from zero address");
    require(_to != address(0), "Cannot transfer to zero address");
    require(_value > 0, "Transfer amount must be > 0");
    require(allowance[_from][msg.sender] >= _value, "Allowance exceeded");
    allowance[_from][msg.sender] -= _value;
    balances[_from] -= _value;
    balances[_to] += _value;
    emit Transfer(_from, _to, _value);
}
```

### Developer Workflow

1. **Deploy a DAO first** (using DAO.solid template)
2. **Create a Token from the DAO**:
   ```solidity
   // From within DAO contract:
   Token my_token = new Token("OxToken", "OX", 18);
   // Or via function call:
   // token.create("OxToken", "OX", 18);
   ```
3. **Use the Token**:
   - `transfer(to, amount)` - Send tokens
   - `balance_of(address)` - Check balance
   - `approve(spender, amount)` then `transfer_from(from, to, amount)` - Allow spender to move tokens
   - `get_total_supply()` - Total supply
   - `get_decimals()` - 18 decimal places

### Files
- `crates/solid/templates/Token.solid` - The full contract source

### Integration with DAO
The Token is designed to work specifically with DAOs:
- Only the creating DAO can mint new tokens
- `dao_has_token` ensures a DAO can only have 1 Token
- The DAO's treasury can hold tokens for transaction facilitation
- Token creation is tied to the DAO's address identity

---

*Generated from crates/solid/templates/Token.solid*
