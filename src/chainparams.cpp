// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
static Checkpoints::MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        ( 0, uint256("0xd77cb63a40042d73a83142383c7872c123cda7253db1d9c0effc8a029ca857b2"))
        ( 8, uint256("0x8b1a062ac3af6d6711e1a62f633bca62487ed46b393bca893573f00ca62cd56a"))
        ( 16, uint256("0xf9f20eb91a0ea3e5e7196a1fc55d63667aca9c00cf739d2a27a84375fc70a7df"))
        ( 32, uint256("0x22c03da069072d8214d7d5617088605a2645671a7d69e2a8914dc59ee1449c9a"))
        ( 64, uint256("0xa32b7960e35ae2f9ef83a8b7507bc3fffc6959ef27c46ed4ebdbabf9e661375d"))
        ( 128, uint256("0x172d100cf86135d03da12936d3174b68beba7752bf208ee5eacfd44012cd066e"))
        ( 256, uint256("0xa83edd96dff905aab89680cf376d990f442bdc132df9b7d46f07046544f277c5"))
        ( 512, uint256("0x01886cc19b158c46472c83829058c6e35f965f18aa5c1df66810f883e6aeb45f"))
        ( 1024, uint256("0xff3c7e6ef394ae25873417dded36a98bc9078b5ea8a4136bb6cdbe6030a62d17"))
        ( 2048, uint256("0x4a162aadd8ecc9d38d827a39d8200c3c29f2e57701e7fa3e71b365ed6c150dfd"))
        ( 3072, uint256("0x853568d83d85a66b74c548c8c999ffc1d2a7a056f334dcb1259e5869becab020"))
        ( 4096, uint256("0xe9ea2f86dc06bab486beafba65e956c24298d01eca2eec7bfc295ba4ccf443d9"))		
        ( 6300, uint256("0x24b0e25b37e33cdcd797c04bb002a51781d0b588ee770f7ec7444202a4cafe6b"))
        ( 7200, uint256("0x197bc599f1b0935852cd247863c731deb90ab65f6d71b51ce64daf7a8e075e2b"))
        ( 8400, uint256("0x702528b55f744f690d896095c4ca8642ccf5f6b420a37b5c6db303013b982d24"))
        ( 12700, uint256("0xb4840c996402136af7e71c19bbad1431b88e0bce56716aa3d9a6eb9f09f73ac2"))
        ( 16800, uint256("0x3229d32141164b7a1d3d82a606fccf096bdf046f4612b9b57d4096f2dfebce98"))
        ( 17300, uint256("0x51d6766e909baff8809fa85f7be393b31c91ce0724af93de8d3539662c80078b"))
        ( 24200, uint256("0x14d1fd1500db0485569c1b0957e19dc4d2fedf7d3dab43795a8974ca049c876b"))
        ( 32000, uint256("0xb5ebffdaad009c33b33f5b06d7f95e9b26f055ff0fc2f21b5a8c496934577037"))
        ( 63000, uint256("0xf3c85888ca38fe2f417de0bc4e47e58f168bd79ae9da3a03fc7364125ef1ffac"))
		( 126000, uint256("0x3e8c86ecd66cf4d9e75878a5cbfd0d4a1edd2c2333de19995ef2d71ff2738067"))
		( 168000, uint256("0xde6228140833a5e2a73979787fd7a4800c748b055aee2d95c75bb4a636fd015d"))
		( 190000, uint256("0x00893e10096acae18333584bd33e608ec18607fab0652adaff31160a378c676f"))
		( 210000, uint256("0x2159f38662721020da02134265a23b2b17fb2641407106fbadc5c17306e3fea7"))
		( 260060, uint256("0x7a5071b17de974e657153174569fa782244fab63d334aa343667cf5fddf64933"))
		( 260080, uint256("0x77048bdf9042dad150aedfe54c5c53fd8ef081ec481197fc48c4ef8b9405758c"))
        ;
static const Checkpoints::CCheckpointData data = {
        &mapCheckpoints,
        1507956080, // * UNIX timestamp of last checkpoint block d77cb63a40042d73a83142383c7872c123cda7253db1d9c0effc8a029ca857b2
        262877,   // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        1152.0     // * estimated number of transactions per day after checkpoint
    };

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 0, uint256("0xd77cb63a40042d73a83142383c7872c123cda7253db1d9c0effc8a029ca857b2"))
        ( 128, uint256("0x172d100cf86135d03da12936d3174b68beba7752bf208ee5eacfd44012cd066e"))
        ( 256, uint256("0xa83edd96dff905aab89680cf376d990f442bdc132df9b7d46f07046544f277c5"))
        ( 512, uint256("0x01886cc19b158c46472c83829058c6e35f965f18aa5c1df66810f883e6aeb45f"))
        ( 1024, uint256("0xff3c7e6ef394ae25873417dded36a98bc9078b5ea8a4136bb6cdbe6030a62d17"))
        ( 2048, uint256("0x4a162aadd8ecc9d38d827a39d8200c3c29f2e57701e7fa3e71b365ed6c150dfd"))
        ( 3072, uint256("0x853568d83d85a66b74c548c8c999ffc1d2a7a056f334dcb1259e5869becab020"))
        ( 4096, uint256("0xe9ea2f86dc06bab486beafba65e956c24298d01eca2eec7bfc295ba4ccf443d9"))
        ( 6300, uint256("0x24b0e25b37e33cdcd797c04bb002a51781d0b588ee770f7ec7444202a4cafe6b"))		
        ( 7200, uint256("0x197bc599f1b0935852cd247863c731deb90ab65f6d71b51ce64daf7a8e075e2b"))
        ( 8400, uint256("0x702528b55f744f690d896095c4ca8642ccf5f6b420a37b5c6db303013b982d24"))
        ( 12700, uint256("0xb4840c996402136af7e71c19bbad1431b88e0bce56716aa3d9a6eb9f09f73ac2"))
        ( 16800, uint256("0x3229d32141164b7a1d3d82a606fccf096bdf046f4612b9b57d4096f2dfebce98"))
        ( 17300, uint256("0x51d6766e909baff8809fa85f7be393b31c91ce0724af93de8d3539662c80078b"))
        ( 24200, uint256("0x14d1fd1500db0485569c1b0957e19dc4d2fedf7d3dab43795a8974ca049c876b"))
        ( 32000, uint256("0xb5ebffdaad009c33b33f5b06d7f95e9b26f055ff0fc2f21b5a8c496934577037"))
        ( 63000, uint256("0xf3c85888ca38fe2f417de0bc4e47e58f168bd79ae9da3a03fc7364125ef1ffac"))		
		( 126000, uint256("0x3e8c86ecd66cf4d9e75878a5cbfd0d4a1edd2c2333de19995ef2d71ff2738067"))
		( 190000, uint256("0x00893e10096acae18333584bd33e608ec18607fab0652adaff31160a378c676f"))
        ;
static const Checkpoints::CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1496753720, // 16800 1468996961 17017
        191794,
        630
    };

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of
        ( 0, uint256("0x0b03fdcf0f035802aada1002031af19b4e9c7bbc069c8a2facbfb48c7dbfb35f"))
        ;
static const Checkpoints::CCheckpointData dataRegtest = {
        &mapCheckpointsRegtest,
        0,
        0,
        0
    };

class CMainParams : public CChainParams {
public:
    CMainParams() {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /** 
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xdb;
        vAlertPubKey = ParseHex("043014c67b78f95c8964ba4f10bc83ce6dbee8d6afeb0570552e2f7562f83a5ae6cc937900545ab5c30a84565315d55107d5269e816c50e4080ca89dc2cc64e9c2");
        nDefaultPort = 8833;
        bnProofOfWorkLimit = ~uint256(0) >> 20;
        nSubsidyHalvingInterval = 210000;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        nTargetTimespanx = 10 * 60; // 10 minutes
		nTargetTimespans = 5 * 60; // 5 minutes
        nTargetSpacing = 2.5 * 60; // 2.5 minutes
        nMaxTipAge = 24 * 60 * 60;

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         * 
         * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
         *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
         *   vMerkleTree: 4a5e1e
         */
        const char* pszTimestamp = "We Are The People! Thu, 16 Jun 2016 00:00:00 GMT";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 21000000 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("0496dbe312a5db151199b7f71fe3329fdc673bcadc51dbd714ca3a70446bd628dcbb41d86252702c6b8a2d50e2fa7be835396accb7781d107d129a3dff88fcBff3") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1466035200;
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 114703;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0xd77cb63a40042d73a83142383c7872c123cda7253db1d9c0effc8a029ca857b2"));
        assert(genesis.hashMerkleRoot == uint256("0x7a756f67df28090833de8df9c15f36f9637306809443b3065dec5db903210566"));
		
		vSeeds.push_back(CDNSSeedData("king.odj.ru", "node.exip.net"));
		vSeeds.push_back(CDNSSeedData("king.odj.ru", "king.odj.ru"));
		vSeeds.push_back(CDNSSeedData("king1.odj.ru", "king1.odj.ru"));
		vSeeds.push_back(CDNSSeedData("king2.odj.ru", "king2.odj.ru"));
		vSeeds.push_back(CDNSSeedData("king3.odj.ru", "king3.odj.ru"));
		vSeeds.push_back(CDNSSeedData("king4.odj.ru", "king4.odj.ru"));
		vSeeds.push_back(CDNSSeedData("king5.odj.ru", "king5.odj.ru"));
		
		vSeeds.push_back(CDNSSeedData("nodea.exip.net", "nodea.exip.net"));
		vSeeds.push_back(CDNSSeedData("nodeb.exip.net", "nodeb.exip.net"));
		vSeeds.push_back(CDNSSeedData("nodec.exip.net", "nodec.exip.net"));
		vSeeds.push_back(CDNSSeedData("nodes.exip.net", "nodes.exip.net"));
		vSeeds.push_back(CDNSSeedData("node1.exip.net", "node1.exip.net"));
		vSeeds.push_back(CDNSSeedData("node2.exip.net", "node2.exip.net"));
		vSeeds.push_back(CDNSSeedData("node3.exip.net", "node3.exip.net"));
		vSeeds.push_back(CDNSSeedData("node4.exip.net", "node4.exip.net"));
		vSeeds.push_back(CDNSSeedData("node5.exip.net", "node5.exip.net"));

        base58Prefixes[PUBKEY_ADDRESS] = list_of(0);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(5);
        base58Prefixes[SECRET_KEY] =     list_of(128);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        // Ladacoin: Mainnet v2 enforced as of block 710k
        nEnforceV2AfterHeight = 710000;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        /*
		*pchMessageStart[0] = 0xfc;
        *pchMessageStart[1] = 0xc1;
        *pchMessageStart[2] = 0xb7;
        *pchMessageStart[3] = 0xdc;
		**/
		pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xdb;
        vAlertPubKey = ParseHex("043014c67b78f95c8964ba4f10bc83ce6dbee8d6afeb0570552e2f7562f83a5ae6cc937900545ab5c30a84565315d55107d5269e816c50e4080ca89dc2cc64e9c2");
        nDefaultPort = 9333;
        bnProofOfWorkLimit = ~uint256(0) >> 20; //empty
        nSubsidyHalvingInterval = 210000; //empty
        nEnforceBlockUpgradeMajority = 750; //51
        nRejectBlockOutdatedMajority = 950; //75
        nToCheckBlockUpgradeMajority = 1000; //100
        nMinerThreads = 0;
        nTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        nTargetTimespanx = 10 * 60; // 10 minutes
		nTargetTimespans = 5 * 60; // 5 minutes
        nTargetSpacing = 2.5 * 60; // 2.5 minutes
        nMaxTipAge = 24 * 60 * 60;
        //nMaxTipAge = 0x7fffffff;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1466035200;
        genesis.nNonce = 114703;
        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0xd77cb63a40042d73a83142383c7872c123cda7253db1d9c0effc8a029ca857b2"));

        vFixedSeeds.clear();
        vSeeds.clear();
		vSeeds.push_back(CDNSSeedData("king.odj.ru", "node.exip.net"));
		vSeeds.push_back(CDNSSeedData("king.odj.ru", "king.odj.ru"));
		vSeeds.push_back(CDNSSeedData("king1.odj.ru", "king1.odj.ru"));
		vSeeds.push_back(CDNSSeedData("king2.odj.ru", "king2.odj.ru"));
		vSeeds.push_back(CDNSSeedData("king3.odj.ru", "king3.odj.ru"));
		vSeeds.push_back(CDNSSeedData("king4.odj.ru", "king4.odj.ru"));
		vSeeds.push_back(CDNSSeedData("king5.odj.ru", "king5.odj.ru"));

		vSeeds.push_back(CDNSSeedData("nodea.exip.net", "nodea.exip.net"));
		vSeeds.push_back(CDNSSeedData("nodeb.exip.net", "nodeb.exip.net"));
		vSeeds.push_back(CDNSSeedData("nodec.exip.net", "nodec.exip.net"));
		vSeeds.push_back(CDNSSeedData("nodes.exip.net", "nodes.exip.net"));
		vSeeds.push_back(CDNSSeedData("node1.exip.net", "node1.exip.net"));
		vSeeds.push_back(CDNSSeedData("node2.exip.net", "node2.exip.net"));
		vSeeds.push_back(CDNSSeedData("node3.exip.net", "node3.exip.net"));
		vSeeds.push_back(CDNSSeedData("node4.exip.net", "node4.exip.net"));
		vSeeds.push_back(CDNSSeedData("node5.exip.net", "node5.exip.net"));
		
        base58Prefixes[PUBKEY_ADDRESS] = list_of(48);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(5);
        base58Prefixes[SECRET_KEY] =     list_of(176);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);
		
        //base58Prefixes[PUBKEY_ADDRESS] = list_of(111);
        //base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        //base58Prefixes[SECRET_KEY]     = list_of(239);
        //base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        //base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false; //true
        fDefaultConsistencyChecks = false;
        fRequireStandard = true; //false
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false; //true

        // Ladacoin: Testnet v2 enforced as of block 400k
        nEnforceV2AfterHeight = 710000;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        nTargetTimespanx = 10 * 60; // 10 minutes
		nTargetTimespans = 5 * 60; // 5 minutes
        nTargetSpacing = 2.5 * 60; // 2.5 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        nMaxTipAge = 24 * 60 * 60;
        genesis.nTime = 1466035000;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 0;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 19444;
        assert(hashGenesisBlock == uint256("0x0b03fdcf0f035802aada1002031af19b4e9c7bbc069c8a2facbfb48c7dbfb35f"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        // Ladacoin: v2 enforced using Bitcoin's supermajority rule
        nEnforceV2AfterHeight = -1;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams {
public:
    CUnitTestParams() {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 18445;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;

        // Ladacoin: v2 enforced using Bitcoin's supermajority rule
        nEnforceV2AfterHeight = -1;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval)  { nSubsidyHalvingInterval=anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority)  { nEnforceBlockUpgradeMajority=anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority)  { nRejectBlockOutdatedMajority=anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority)  { nToCheckBlockUpgradeMajority=anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks)  { fDefaultConsistencyChecks=afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) {  fAllowMinDifficultyBlocks=afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams *pCurrentParams = 0;

CModifiableParams *ModifiableParams()
{
   assert(pCurrentParams);
   assert(pCurrentParams==&unitTestParams);
   return (CModifiableParams*)&unitTestParams;
}

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        case CBaseChainParams::UNITTEST:
            return unitTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
