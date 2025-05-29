const readline = require("readline");
const {
  SigningStargateClient,
  defaultRegistryTypes,
} = require("@cosmjs/stargate");
const { DirectSecp256k1HdWallet, Registry } = require("@cosmjs/proto-signing");
const { Buffer } = require("buffer"); // MOVED UP
const crypto = require("crypto"); // MOVED UP
const { toBech32, fromBech32 } = require("@cosmjs/encoding"); // MOVED UP
const { wasmTypes } = require("@cosmjs/cosmwasm-stargate"); // Import wasmTypes

// --- ANSI Color Codes (ensure these are defined before this block if moved higher) ---
const RESET = "\x1b[0m";
const BRIGHT = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const MAGENTA = "\x1b[35m";
const CYAN = "\x1b[36m";
const WHITE = "\x1b[37m";

// --- Readline setup ---
let rl; // Declare rl here to be accessible in finally block

function askQuestion(query) {
  if (!rl) {
    rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
  }
  // Prompts in Cyan
  return new Promise((resolve) =>
    rl.question(BRIGHT + CYAN + query + RESET, (ans) => {
      resolve(ans);
    })
  );
}

// --- Helper Functions for Dynamic Instruction Construction ---

/**
 * Converts a decimal number to a hex string, zero-padded to a specific length.
 * @param {number} d The decimal number.
 * @param {number} padding The desired length of the hex string (e.g., 64 for 32 bytes).
 * @returns {string} Zero-padded hex string.
 */
function decimalToHex(d, padding) {
  let hex = Number(d).toString(16);
  while (hex.length < padding) {
    hex = "0" + hex;
  }
  return hex;
}

/**
 * Encodes an address string for the instruction payload.
 * Format: length_of_address (32 bytes hex) + address_hex_padded (to 64 bytes).
 * @param {string} addrStr The address string.
 * @returns {string} Hex encoded address part for the instruction.
 */
function encodeAddressForInstruction(addrStr) {
  const lenHex = decimalToHex(addrStr.length, 64); // Length as 32-byte hex (64 hex chars)
  const valHex = Buffer.from(addrStr).toString("hex");
  // Pad valHex to be exactly 128 hex characters (64 bytes)
  const paddedValHex = valHex.padEnd(128, "0");
  return lenHex + paddedValHex;
}

// Constants derived from the working example instruction structure (hasil1.json)
const INSTRUCTION_PREFIX_CONST =
  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000200";
const INSTRUCTION_MIDDLE_CONST =
  "000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002c0";
const DENOM_UBBN_ENCODED =
  "0000000000000000000000000000000000000000000000000000000000000004" +
  Buffer.from("ubbn").toString("hex").padEnd(64, "0");
const DENOMS_BLOCK_CONST = DENOM_UBBN_ENCODED.repeat(3);

// Conversion constant for BBN to microBBN
const BBN_TO_UBBN_MULTIPLIER = 1000000; // 1 BBN = 1,000,000 ubbn

/**
 * Constructs the dynamic instruction hex string.
 * @param {string|number} amount The amount (e.g., 1000 or 10000).
 * @param {string} primaryAddress Address corresponding to the first amount/denom pair.
 * @param {string} secondaryAddress Address for the second pair.
 * @param {string} tertiaryAddress Address for the third pair.
 * @returns {string} The fully constructed instruction hex string, starting with "0x".
 */
function constructDynamicInstruction(
  amount,
  primaryAddress,
  secondaryAddress,
  tertiaryAddress
) {
  const hexAmount = decimalToHex(amount, 64);

  const encodedAddr1 = encodeAddressForInstruction(primaryAddress);
  const encodedAddr2 = encodeAddressForInstruction(secondaryAddress);
  const encodedAddr3 = encodeAddressForInstruction(tertiaryAddress);

  // Structure based on hasil1.json analysis:
  // PREFIX + AMOUNT + MIDDLE + AMOUNT + ADDR1 + ADDR2 + DENOMS + ADDR3
  const instructionHex =
    INSTRUCTION_PREFIX_CONST +
    hexAmount + // First amount
    INSTRUCTION_MIDDLE_CONST +
    hexAmount + // Second amount (repeated)
    encodedAddr1 +
    encodedAddr2 +
    DENOMS_BLOCK_CONST +
    encodedAddr3;
  return "0x" + instructionHex;
}

/**
 * Converts human-readable BBN amount to ubbn (microBBN) format
 * @param {string|number} humanAmount - Amount in BBN (e.g., "0.001", "1.5", "10")
 * @returns {string} Amount in ubbn format
 */
function convertToMicroBBN(humanAmount) {
  const bbnAmount = parseFloat(humanAmount);
  if (isNaN(bbnAmount) || bbnAmount <= 0) {
    throw new Error(`Invalid amount: ${humanAmount}`);
  }
  const ubbnAmount = Math.floor(bbnAmount * BBN_TO_UBBN_MULTIPLIER);
  return ubbnAmount.toString();
}

/**
 * Formats amount for display with proper units
 * @param {string} ubbnAmount - Amount in ubbn
 * @returns {string} Formatted display string
 */
function formatAmountDisplay(ubbnAmount) {
  const bbnAmount = parseInt(ubbnAmount) / BBN_TO_UBBN_MULTIPLIER;
  return `${bbnAmount} BBN (${parseInt(ubbnAmount).toLocaleString()} ubbn)`;
}

// --- Helper function to create MsgExecuteContract ---
function createMsgExecuteContractPayload(sender, contract, fundsP, msgP) {
  return {
    typeUrl: "/cosmwasm.wasm.v1.MsgExecuteContract",
    value: {
      sender: sender,
      contract: contract,
      funds: fundsP,
      // The 'msg' field for the contract needs to be a JSON string, then Buffer/Uint8Array.
      msg: Buffer.from(JSON.stringify(msgP)),
    },
  };
}

/**
 * Creates and sends a single MsgExecuteContract transaction.
 * @param {object} client - The SigningStargateClient instance.
 * @param {string} senderAddr - The address of the transaction sender.
 * @param {string} contractAddr - The address of the smart contract.
 * @param {object} txParams - Parameters for the transaction.
 * @param {string|number} txParams.amount - The amount for the instruction and funds.
 * @param {string} txParams.denom - The denomination of the funds (e.g., "ubbn").
 * @param {{primary: string, secondary: string, tertiary: string}} txParams.addresses - Addresses for the instruction.
 * @param {string|number} txParams.channel_id - The channel ID for the send message.
 * @param {string} [txParams.timeout_height="0"] - Timeout height.
 * @param {number} [txParams.timeout_offset_ms=3600000] - Offset in milliseconds for timeout_timestamp (default 1hr).
 * @param {string} [txParams.memo=""] - Optional memo for the transaction.
 * @param {object} feeConfig - Fee configuration for the transaction (amount & gas).
 */
async function executeContractSendTransaction(
  client,
  senderAddr,
  contractAddr,
  txParams,
  feeConfig,
  overrideInstruction = null // Added optional parameter
) {
  try {
    const {
      amount,
      denom,
      addresses,
      channel_id,
      timeout_height = "0",
      timeout_offset_ms = 60 * 60 * 1000, // Default 1 hour
      memo = "Dynamic contract execution",
    } = txParams;

    const salt = "0x" + crypto.randomBytes(32).toString("hex");
    const timeout_timestamp =
      (Date.now() + timeout_offset_ms).toString() + "000000";

    // Use overrideInstruction if provided, otherwise generate dynamically
    const instruction = overrideInstruction
      ? overrideInstruction
      : constructDynamicInstruction(
          amount,
          addresses.primary,
          addresses.secondary,
          addresses.tertiary
        );

    const funds = [{ denom: denom, amount: amount.toString() }];
    const msgPayloadForContract = {
      send: {
        channel_id: channel_id,
        timeout_height: timeout_height,
        timeout_timestamp: timeout_timestamp,
        salt: salt,
        instruction: instruction,
      },
    };

    // Use senderAddr (derived from mnemonic's first account) for the 'sender' field of the message
    const executeMsg = createMsgExecuteContractPayload(
      senderAddr,
      contractAddr,
      funds,
      msgPayloadForContract
    );

    const result = await client.signAndBroadcast(
      senderAddr,
      [executeMsg],
      feeConfig,
      memo
    );
    console.log(
      GREEN +
        `✅ Transaction successful! Hash: ${result.transactionHash}` +
        RESET
    );
    console.log(
      DIM + `   Amount sent: ${formatAmountDisplay(amount.toString())}` + RESET
    );
    return result;
  } catch (error) {
    console.error(RED + `❌ Transaction failed: ${error.message}` + RESET);
    throw error;
  }
}

async function main() {
  console.log(
    BRIGHT + MAGENTA + "\n========================================" + RESET
  );
  console.log(BRIGHT + MAGENTA + " Cosmos Transaction Sender CLI " + RESET);
  console.log(
    BRIGHT + MAGENTA + "========================================" + RESET
  );

  // --- Default Values ---
  const DEFAULT_RPC_ENDPOINT = "https://babylon-testnet-rpc.nodes.guru/";
  const DEFAULT_ADDRESS_PREFIX = "bbn";
  const DEFAULT_FEE_DENOM = "ubbn";
  const DEFAULT_FEE_AMOUNT = "4970";
  const DEFAULT_GAS_LIMIT = "496922";
  const DEFAULT_TX_AMOUNT = "0.001"; // Default amount in BBN (will be converted to ubbn)
  const DEFAULT_TX_DENOM = "ubbn";
  const DEFAULT_TX_TERTIARY_ADDRESS =
    "xion1j0hp6qztgaza7t0y8dvc22eavvvqyds3kze58dlqkulys8r2kc8s9mp0sm";
  const DEFAULT_CHANNEL_ID = 4;
  const DEFAULT_TIMEOUT_OFFSET_HOURS = 72;
  const DEFAULT_MEMO = "";

  let txGenericParams = [];
  let client;
  let walletAddresses = [];

  // Define fee configuration globally to be accessible in both modes
  const defaultFeeConfig = {
    amount: [{ denom: DEFAULT_FEE_DENOM, amount: DEFAULT_FEE_AMOUNT }],
    gas: DEFAULT_GAS_LIMIT,
  };

  try {
    // --- Auto-detect phrases from phrase.txt ---
    const fs = require("fs");
    const phraseContent = fs.readFileSync("phrase.txt", "utf8").trim();
    const allPhrases = phraseContent
      .split("\n")
      .filter((line) => line.trim() !== "");

    if (allPhrases.length === 0) {
      console.log(
        RED + "❌ No valid phrases found in phrase.txt. Exiting." + RESET
      );
      return;
    }

    console.log(
      BRIGHT +
        BLUE +
        `\n--- Found ${allPhrases.length} wallet(s) in phrase.txt ---` +
        RESET
    );

    let mnemonics = [];
    if (allPhrases.length === 1) {
      // Single wallet mode
      mnemonics = allPhrases;
      console.log(GREEN + "📱 Single wallet mode activated" + RESET);
    } else {
      // Multiple wallet mode - let user choose how many to use
      console.log(
        GREEN +
          `📱 Multiple wallet mode activated (${allPhrases.length} wallets available)` +
          RESET
      );

      const numWalletsStr = await askQuestion(
        `How many wallets do you want to use? (1-${allPhrases.length}, default: all): `
      );
      const numWallets =
        numWalletsStr.trim() === ""
          ? allPhrases.length
          : parseInt(numWalletsStr, 10);

      if (
        isNaN(numWallets) ||
        numWallets <= 0 ||
        numWallets > allPhrases.length
      ) {
        console.log(
          RED +
            `❌ Invalid number. Please enter 1-${allPhrases.length}. Exiting.` +
            RESET
        );
        return;
      }

      mnemonics = allPhrases.slice(0, numWallets);
      console.log(
        GREEN + `✅ Using ${numWallets} wallet(s) from phrase.txt` + RESET
      );
    }

    // --- Setup Wallets ---
    console.log(BRIGHT + BLUE + "\n--- Setting up wallets ---" + RESET);
    const myRegistry = new Registry([...defaultRegistryTypes, ...wasmTypes]);

    for (let i = 0; i < mnemonics.length; i++) {
      const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonics[i], {
        prefix: DEFAULT_ADDRESS_PREFIX,
      });
      const accounts = await wallet.getAccounts();
      if (accounts.length === 0) {
        throw new Error(`No accounts found for wallet ${i + 1}.`);
      }

      const primaryAddress = accounts[0].address;
      const { data: senderData } = fromBech32(primaryAddress);
      const secondaryAddress = toBech32("xion", senderData);

      walletAddresses.push({
        wallet,
        primaryAddress,
        secondaryAddress,
        index: i + 1,
      });
    }

    // Display wallet information with better UI
    console.log(
      BRIGHT +
        WHITE +
        "\n┌─────────────────────────────────────────────────────────────────┐" +
        RESET
    );
    console.log(
      BRIGHT +
        WHITE +
        "│                           WALLET INFO                          │" +
        RESET
    );
    console.log(
      BRIGHT +
        WHITE +
        "├─────────────────────────────────────────────────────────────────┤" +
        RESET
    );

    walletAddresses.forEach((w, idx) => {
      console.log(
        BRIGHT +
          WHITE +
          "│ " +
          CYAN +
          `Wallet ${w.index}:` +
          RESET +
          " ".repeat(52 - `Wallet ${w.index}:`.length) +
          BRIGHT +
          WHITE +
          " │" +
          RESET
      );
      console.log(
        BRIGHT +
          WHITE +
          "│ " +
          GREEN +
          "BBN:" +
          RESET +
          ` ${w.primaryAddress}` +
          " ".repeat(58 - w.primaryAddress.length) +
          BRIGHT +
          WHITE +
          " │" +
          RESET
      );
      console.log(
        BRIGHT +
          WHITE +
          "│ " +
          YELLOW +
          "XION:" +
          RESET +
          ` ${w.secondaryAddress}` +
          " ".repeat(57 - w.secondaryAddress.length) +
          BRIGHT +
          WHITE +
          " │" +
          RESET
      );
      if (idx < walletAddresses.length - 1) {
        console.log(
          BRIGHT +
            WHITE +
            "├─────────────────────────────────────────────────────────────────┤" +
            RESET
        );
      }
    });

    console.log(
      BRIGHT +
        WHITE +
        "└─────────────────────────────────────────────────────────────────┘" +
        RESET
    );

    // Setup client with first wallet
    client = await SigningStargateClient.connectWithSigner(
      DEFAULT_RPC_ENDPOINT,
      walletAddresses[0].wallet,
      { registry: myRegistry }
    );
    console.log(
      GREEN +
        `✅ Connected to RPC with ${walletAddresses.length} wallet(s) ready` +
        RESET
    );

    // --- Configure Transactions ---
    console.log(BRIGHT + BLUE + "\n--- Transaction Configuration ---" + RESET);

    if (walletAddresses.length === 1) {
      // Single wallet mode - ask for number of transactions
      const numTransactionsStr = await askQuestion(
        "How many transactions do you want to send? "
      );
      const numTransactions = parseInt(numTransactionsStr, 10);

      if (isNaN(numTransactions) || numTransactions <= 0) {
        console.log(RED + "Invalid number of transactions. Exiting." + RESET);
        return;
      }

      // Configure each transaction for single wallet
      for (let i = 0; i < numTransactions; i++) {
        console.log(CYAN + `\n--- Transaction ${i + 1} ---` + RESET);

        const selectedWallet = walletAddresses[0];
        console.log(
          `🎯 Using wallet 1: ${CYAN}${selectedWallet.primaryAddress.slice(
            0,
            20
          )}...${RESET}`
        );

        const humanAmount =
          (await askQuestion(
            `Amount for tx ${i + 1} in BBN (default: ${DEFAULT_TX_AMOUNT}): `
          )) || DEFAULT_TX_AMOUNT;

        // Convert human-readable amount to ubbn
        let convertedAmount;
        try {
          convertedAmount = convertToMicroBBN(humanAmount);
        } catch (error) {
          console.log(RED + `❌ ${error.message}. Exiting.` + RESET);
          return;
        }

        txGenericParams.push({
          wallet: selectedWallet,
          amount: convertedAmount,
          humanAmount: humanAmount,
          denom: DEFAULT_TX_DENOM,
          addresses: {
            primary: selectedWallet.primaryAddress,
            secondary: selectedWallet.secondaryAddress,
            tertiary: DEFAULT_TX_TERTIARY_ADDRESS,
          },
          channel_id: DEFAULT_CHANNEL_ID,
          timeout_offset_ms: DEFAULT_TIMEOUT_OFFSET_HOURS * 60 * 60 * 1000,
          memo: DEFAULT_MEMO,
        });

        console.log(
          `✅ Configured transaction ${i + 1}: ${formatAmountDisplay(convertedAmount)} from wallet ${selectedWallet.index}`
        );
      }
    } else {
      // Multiple wallet mode - ask for rounds and amount
      const numRoundsStr = await askQuestion(
        `How many rounds do you want to send? (each round sends to all ${walletAddresses.length} wallets): `
      );
      const numRounds = parseInt(numRoundsStr, 10);

      if (isNaN(numRounds) || numRounds <= 0) {
        console.log(RED + "Invalid number of rounds. Exiting." + RESET);
        return;
      }

      const humanAmount =
        (await askQuestion(
          `Amount per transaction in BBN (default: ${DEFAULT_TX_AMOUNT}): `
        )) || DEFAULT_TX_AMOUNT;

      // Convert human-readable amount to ubbn
      let convertedAmount;
      try {
        convertedAmount = convertToMicroBBN(humanAmount);
      } catch (error) {
        console.log(RED + `❌ ${error.message}. Exiting.` + RESET);
        return;
      }

      console.log(CYAN + `\n📋 Configuration Summary:` + RESET);
      console.log(
        `   • ${numRounds} rounds × ${walletAddresses.length} wallets = ${
          numRounds * walletAddresses.length
        } total transactions`
      );
      console.log(`   • ${formatAmountDisplay(convertedAmount)} per transaction`);
      
      const totalUbbn = numRounds * walletAddresses.length * parseInt(convertedAmount);
      const totalBbn = totalUbbn / BBN_TO_UBBN_MULTIPLIER;
      console.log(
        `   • Total amount: ${totalBbn} BBN (${totalUbbn.toLocaleString()} ubbn)\n`
      );

      // Generate all transactions for all rounds
      for (let round = 0; round < numRounds; round++) {
        for (
          let walletIdx = 0;
          walletIdx < walletAddresses.length;
          walletIdx++
        ) {
          const selectedWallet = walletAddresses[walletIdx];

          txGenericParams.push({
            wallet: selectedWallet,
            amount: convertedAmount,
            humanAmount: humanAmount,
            denom: DEFAULT_TX_DENOM,
            addresses: {
              primary: selectedWallet.primaryAddress,
              secondary: selectedWallet.secondaryAddress,
              tertiary: DEFAULT_TX_TERTIARY_ADDRESS,
            },
            channel_id: DEFAULT_CHANNEL_ID,
            timeout_offset_ms: DEFAULT_TIMEOUT_OFFSET_HOURS * 60 * 60 * 1000,
            memo: `Round ${round + 1} - Wallet ${selectedWallet.index}`,
            roundNumber: round + 1,
            walletNumber: selectedWallet.index,
          });
        }
      }

      console.log(
        GREEN + `✅ Configured ${txGenericParams.length} transactions` + RESET
      );
    }

    // --- Execute Transactions ---
    console.log(
      BRIGHT + BLUE + "\n--- Starting Transaction Execution ---" + RESET
    );

    for (let i = 0; i < txGenericParams.length; i++) {
      const params = txGenericParams[i];

      // Display progress for multiple wallet mode
      if (walletAddresses.length > 1) {
        console.log(
          BRIGHT +
            MAGENTA +
            `\n🔄 Round ${params.roundNumber} - Wallet ${params.walletNumber}/${
              walletAddresses.length
            } (${i + 1}/${txGenericParams.length})` +
            RESET
        );
        console.log(
          `   Address: ${CYAN}${params.wallet.primaryAddress.slice(
            0,
            20
          )}...${RESET}`
        );
        console.log(
          `   Amount: ${GREEN}${formatAmountDisplay(params.amount)}${RESET}`
        );
      } else {
        console.log(
          BRIGHT +
            MAGENTA +
            `\n🔄 Transaction ${i + 1}/${txGenericParams.length}` +
            RESET
        );
        console.log(
          `   Amount: ${GREEN}${formatAmountDisplay(params.amount)}${RESET}`
        );
      }

      // Update client if we're using a different wallet
      if (client.signingAddress !== params.wallet.primaryAddress) {
        client = await SigningStargateClient.connectWithSigner(
          DEFAULT_RPC_ENDPOINT,
          params.wallet.wallet,
          { registry: myRegistry }
        );
      }

      try {
        await executeContractSendTransaction(
          client,
          params.wallet.primaryAddress,
          contractAddress,
          params,
          defaultFeeConfig
        );

        if (i < txGenericParams.length - 1) {
          const countdownDuration = 10;
          console.log(
            DIM +
              `Cooldown: Next transaction in ${countdownDuration} seconds...` +
              RESET
          );
          for (let j = countdownDuration; j > 0; j--) {
            process.stdout.write(
              DIM + `\rCooldown: Next transaction in ${j}s...          ` + RESET
            );
            await new Promise((resolve) => setTimeout(resolve, 1000));
          }
          process.stdout.write("\r" + " ".repeat(40) + "\r");
        }
      } catch (error) {
        console.error(
          RED + `❌ Transaction ${i + 1} failed: ${error.message}` + RESET
        );
      }
    }

    console.log(BRIGHT + GREEN + "\n✅ All transactions completed!" + RESET);
  } catch (e) {
    console.error(RED + "\nAn unexpected error occurred in main:" + RESET, e);
  } finally {
    if (rl) {
      rl.close();
    }
  }
}

// Constants for contractAddress - can be moved or made dynamic if needed
const contractAddress =
  "bbn1336jj8ertl8h7rdvnz4dh5rqahd09cy0x43guhsxx6xyrztx292q77945h";

// --- Main Execution ---
main().catch(console.error);
