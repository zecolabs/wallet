# ZP = Zeco Point
# We allocate 5% of supply as a reward for early supporters of the program.
# But because determining the Token Supply at the initial stage is very difficult for us
# we use point mechanism as a representation for 5% token supply
# This code contains a way to calculate token rewards based on the amount of ZP you have.

def to_string(amount: int) -> str:
    MUL = 10**18
    whole = amount // MUL
    fraction = amount % MUL
    if fraction == 0:
        return str(whole)
    fraction_str = str(fraction).zfill(18).rstrip("0")
    return f"{whole}.{fraction_str}"

# Token Suplly are based on 18 decimal
# No matter how much the supply is, you will still get the appropriate share, calculated from the amount of ZP you have.

max_zp = 100_000_000 
zp_rewardpool = 5_000_000
supply = 10_000_000  # try use different suplly and calcutale it again
token_supply = supply* (10**18)
your_zp_balance = 12_234 # replace with the amount of ZP you have.
supply_allocation = (token_supply * zp_rewardpool) // max_zp
your_final_allocation = (token_supply * your_zp_balance) // max_zp
print("Distribution Detail\n$ZP allocated = %d\nToken suplly = %d\nYou have %d $ZP\nAllocated from supply %s Token\nYour final allocation is %s Token"% (
	zp_rewardpool, supply, your_zp_balance,
	to_string(supply_allocation),
	to_string(your_final_allocation)
))