// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, uint32_t nTime, const CScript& scriptChallenge, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = 0;
    txNew.vout[0].scriptPubKey = CScript() << OP_RETURN;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.proof = CProof(scriptChallenge, CScript());
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const CScript& scriptChallenge, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    const char* pszTimestamp = "Lo choc per gli Azzurri fuori dai Mondiali";
    return CreateGenesisBlock(pszTimestamp, nTime, scriptChallenge, nNonce, nBits, nVersion);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        const CScript scriptChallenge = CScript() << OP_1 << ParseHex("027c6ec6d7a34f94df66b3bc4dd9f1d92234f43e8df186da75b5a8e4c19309b731 ") << ParseHex("03ac7b5e8094f77e68b78cc905385c57e721280ba051b134068b6178176f700411") << ParseHex("03c28d8737981e0150569e76aba1349c339b5765d91d603745fe4c83f0631bad30") << OP_3 << OP_CHECKMULTISIG;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 1;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x9b;
        pchMessageStart[1] = 0x6e;
        pchMessageStart[2] = 0x89;
        pchMessageStart[3] = 0x4e;
        vAlertPubKey = ParseHex("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");
        nDefaultPort = 9044;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;

        scriptCoinbaseDestination = CScript() << ParseHex("03774b3aa7d9a2e4d2a99b910342d0c5430e8fc24befe01359ee3aa30c7ad529ff") << OP_CHECKSIG;
        genesis = CreateGenesisBlock(1511346312, scriptChallenge, 1, 0x207fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
        // Temporarely disabled, to be restored later
        assert(consensus.hashGenesisBlock == uint256S("0xe5ac035bd3f1ca70b1c72931160c4c2dd23babc74066f8d4ad0e137c373a9048"));
        assert(genesis.hashMerkleRoot == uint256S("0x3d52a9559a2277f3bb9717ea166009f120a2caced9f6dec6c66688dd40a151b5"));

        vSeeds.clear();

        // https://en.bitcoin.it/wiki/List_of_address_prefixes
        // https://github.com/libbitcoin/libbitcoin/wiki/Altcoin-Version-Mappings
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,70); // start with V
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,63); // start with S
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,171); // AB
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >(); // xprv
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >(); // xpub

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            // to be filled
        };

        pubKHash_gold = "3988c30bf255572c5e192c3957c57095c5d2e760";
        pubKey_gold = "035c1f2a7d3761cd47c0acded27c7e4ee95f1a1c5f545a6f660b10b516965b69f0";
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        const CScript scriptChallenge = CScript() << OP_1 << ParseHex("0274b9539ccf659745550818b5782d950eca2d7a0ad21fd7ab5f06348cc8ba965b") << ParseHex("0269a3bc44d5c01aef34db1c883df236187ef49c875662b39f55d16dc1fda56422") << ParseHex("0301914408f03b2aaa24e1ba628813fa6cb795eb0b40d4768568000b68b6f8e075") << OP_3 << OP_CHECKMULTISIG;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.BIP34Height = 1;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        pchMessageStart[0] = 0x11;
        pchMessageStart[1] = 0x0a;
        pchMessageStart[2] = 0x03;
        pchMessageStart[3] = 0x4e;
        vAlertPubKey = ParseHex("04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a");
        nDefaultPort = 9045;
        nMaxTipAge = 0x7fffffff;
        nPruneAfterHeight = 1000;

        scriptCoinbaseDestination = CScript() << ParseHex("03277a5c7acd5ec83664b8bfe4c8a4424a7f8172579e3df0e857a28a1e5a62e376") << OP_CHECKSIG;
        genesis = CreateGenesisBlock(1510768800, scriptChallenge, 100, 0x207fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
        // Temporarely disabled, to be restored later
        assert(consensus.hashGenesisBlock == uint256S("0xfecda7660014b377f1043fdbe176431cd110242c59d273c5a815466dda41344d"));
        assert(genesis.hashMerkleRoot == uint256S("0x3d52a9559a2277f3bb9717ea166009f120a2caced9f6dec6c66688dd40a151b5"));

        vFixedSeeds.clear();
        vSeeds.clear();
        
        // https://en.bitcoin.it/wiki/List_of_address_prefixes
        // https://github.com/libbitcoin/libbitcoin/wiki/Altcoin-Version-Mappings
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111); // start with 'm' or 'n'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196); // start with 2
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239); // EF
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();// tprv
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >(); // tpub

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (CCheckpointData) {
            // to be filled
        };

        pubKHash_gold = "04357230ff75ff8d2ae9551d3d897cd0e12bc8aa";
        pubKey_gold = "03616bb7bcca98df378ad0da6a95f479abc453eba121f7a923f97cdbb068453f88";

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        const CScript scriptChallenge(CScript() << OP_TRUE);
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 1; // BIP34 has not necessarily activated on regtest
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        pchMessageStart[0] = 0xbf;
        pchMessageStart[1] = 0xda;
        pchMessageStart[2] = 0x03;
        pchMessageStart[3] = 0x4e;
        nMaxTipAge = 24 * 60 * 60;
        nDefaultPort = 9046;
        nPruneAfterHeight = 1000;

        scriptCoinbaseDestination = CScript() << ParseHex("0332c05735148f7218ae9ca1902b67c14ef6b73603dd05a167d0feb3326ed9f75c") << OP_CHECKSIG;
        genesis = CreateGenesisBlock(1504224000, scriptChallenge, 50, 0x207fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
        // Temporarely disabled, to be restored later
        // assert(consensus.hashGenesisBlock == uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));
        // assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            // to be filled
        };

        // https://en.bitcoin.it/wiki/List_of_address_prefixes
        // https://github.com/libbitcoin/libbitcoin/wiki/Altcoin-Version-Mappings
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111); // start with 'm' or 'n'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196); // start with 2
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239); // EF
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >(); // tprv
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >(); // tpub

        pubKHash_gold = "da72dc932f2dc45c75cac5751f9b6ba5174e636f";
        pubKey_gold = "02414b3f5454f6bb708d7cb2e8e04049085f45e909331c2cf21b610190a5ac1338";
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}
