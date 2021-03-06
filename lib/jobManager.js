var events = require('events');
var crypto = require('crypto');

var bignum = require('bignum');



var util = require('./util.js');
var blockTemplate = require('./blockTemplate.js');



//Unique extranonce per subscriber
var ExtraNonceCounter = function(configInstanceId){

    var instanceId = configInstanceId || crypto.randomBytes(4).readUInt32LE(0);
    var counter = instanceId << 27;

    this.next = function(){
        var extraNonce = util.packUInt32BE(Math.abs(counter++));
        return extraNonce.toString('hex');
    };

    this.size = 4; //bytes
};

//Unique job per new block template
var JobCounter = function(){
    var counter = 0;

    this.next = function(){
        counter++;
        if (counter % 0xffff === 0)
            counter = 1;
        return this.cur();
    };

    this.cur = function () {
        return counter.toString(16);
    };
};

/**
 * Emits:
 * - newBlock(blockTemplate) - When a new block (previously unknown to the JobManager) is added, use this event to broadcast new jobs
 * - share(shareData, blockHex) - When a worker submits a share. It will have blockHex if a block was found
**/
var JobManager = module.exports = function JobManager(options){


    //private members

    var _this = this;
    var jobCounter = new JobCounter();

    var shareMultiplier = algos[options.coin.algorithm].multiplier;
    
    //public members

    this.extraNonceCounter = new ExtraNonceCounter(options.instanceId);
    this.extraNoncePlaceholder = new Buffer('f000000ff111111f', 'hex');
    this.extraNonce2Size = this.extraNoncePlaceholder.length - this.extraNonceCounter.size;

    this.currentJob;
    this.validJobs = {};

    var hashDigest = algos[options.coin.algorithm].hash(options.coin);

    var coinbaseHasher = (function(){
        switch(options.coin.algorithm){
            case 'keccak':
            case 'fugue':
            case 'groestl':
                if (options.coin.normalHashing === true)
                    return util.sha256d;
                else
                    return util.sha256;
            default:
                return util.sha256d;
        }
    })();


    var blockHasher = (function () {
        switch (options.coin.algorithm) {
            case 'scrypt':
                if (options.coin.reward === 'POS') {
                    return function (d) {
                        return util.reverseBuffer(hashDigest.apply(this, arguments));
                    };
                }
            case 'scrypt-jane':
                if (options.coin.reward === 'POS') {
                    return function (d) {
                        return util.reverseBuffer(hashDigest.apply(this, arguments));
                    };
                }
            case 'scrypt-n':
                return function (d) {
                    return util.reverseBuffer(util.sha256d(d));
                };
            default:
                return function () {
                    return util.reverseBuffer(hashDigest.apply(this, arguments));
                };
        }
    })();

    this.updateCurrentJob = function(rpcData){

        var tmpBlockTemplate = new blockTemplate(
            jobCounter.next(),
            rpcData,
            options.poolAddressScript,
            _this.extraNoncePlaceholder,
            options.coin.reward,
            options.coin.txMessages,
            options.recipients
        );

        _this.currentJob = tmpBlockTemplate;

        _this.emit('updatedBlock', tmpBlockTemplate, true);

        _this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;

    };

    //returns true if processed a new block
    this.processTemplate = function(rpcData){

        /* Block is new if A) its the first block we have seen so far or B) the blockhash is different and the
           block height is greater than the one we have */
        var isNewBlock = typeof(_this.currentJob) === 'undefined';
        if  (!isNewBlock && _this.currentJob.rpcData.previousblockhash !== rpcData.previousblockhash){
            isNewBlock = true;

            //If new block is outdated/out-of-sync than return
            if (rpcData.height < _this.currentJob.rpcData.height)
                return false;
        }

        if (!isNewBlock) return false;


        var tmpBlockTemplate = new blockTemplate(
            jobCounter.next(),
            rpcData,
            options.poolAddressScript,
            _this.extraNoncePlaceholder,
            options.coin.reward,
            options.coin.txMessages,
            options.recipients
        );

        this.currentJob = tmpBlockTemplate;

        this.validJobs = {};
        _this.emit('newBlock', tmpBlockTemplate);

        this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;

        return true;

    };

    this.processShare = function(jobId, previousDifficulty, difficulty, extraNonce1, extraNonce2, nTime, nonce, ipAddress, port, workerName){
        var shareError = function(error){
            _this.emit('share', {
                job: jobId,
                ip: ipAddress,
                worker: workerName,
                difficulty: difficulty,
                error: error[1]
            });
            return {error: error, result: null};
        };

        var submitTime = Date.now() / 1000 | 0;

        if (extraNonce2.length / 2 !== _this.extraNonce2Size)
            return shareError([20, 'incorrect size of extranonce2']);

        var job = this.validJobs[jobId];

        if (typeof job === 'undefined' || job.jobId != jobId ) {
            return shareError([21, 'job not found']);
        }

        if (nTime.length !== 8) {
            return shareError([20, 'incorrect size of ntime']);
        }

        var nTimeInt = parseInt(nTime, 16);
        if (nTimeInt < job.rpcData.curtime || nTimeInt > submitTime + 7200) {
            return shareError([20, 'ntime out of range']);
        }

        if (nonce.length !== 8) {
            return shareError([20, 'incorrect size of nonce']);
        }

        if (!job.registerSubmit(extraNonce1, extraNonce2, nTime, nonce)) {
            return shareError([22, 'duplicate share']);
        }

	var powLimit = algos.kawpow.diff; // TODO: Get algos object from argument
   	 var adjPow = powLimit / difficulty;
   	 if ((64 - adjPow.toString(16).length) === 0) {
        var zeroPad = '';
    	}
    	else {
        var zeroPad = '0';
        zeroPad = zeroPad.repeat((64 - (adjPow.toString(16).length)));
    	}
   	 var target_share_hex = (zeroPad + adjPow.toString(16)).substr(0,64);	

        var extraNonce1Buffer = new Buffer(extraNonce1, 'hex');
        var extraNonce2Buffer = new Buffer(extraNonce2, 'hex');

        var coinbaseBuffer = job.serializeCoinbase(extraNonce1Buffer, extraNonce2Buffer);
        var coinbaseHash = coinbaseHasher(coinbaseBuffer);

        var merkleRoot = util.reverseBuffer(job.merkleTree.withFirst(coinbaseHash)).toString('hex');

        var headerBuffer = job.serializeHeader(merkleRoot, nTime, nonce);
        var headerHash = hashDigest(headerBuffer, nTimeInt);
        var headerBigNum = bignum.fromBuffer(headerHash, {endian: 'little', size: 32});

        var blockHashInvalid;
        var blockHash;
        var blockHex;

	 console.log("Using "+options.kawpow_validator+" for validation.");

    if (options.kawpow_validator == "kawpowd") {

      async.series([
        function(callback) {
          var kawpowd_url = 'http://'+options.kawpow_wrapper_host+":"+options.kawpow_wrapper_port+'/'+'?header_hash='+header_hash+'&mix_hash='+miner_given_mixhash+'&nonce='+miner_given_nonce+'&height='+job.rpcData.height+'&share_boundary='+target_share_hex+'&block_boundary='+job.target_hex;
  
          http.get(kawpowd_url, function (res) {
          res.setEncoding("utf8");
          let body = "";
          res.on("data", data => {
            body += data;
          });
          res.on("end", () => {
            body = JSON.parse(body);
            // console.log("JSON RESULT FROM KAWPOWD: "+JSON.stringify(body));
            console.log("********** INCOMING SHARE FROM WORKER ************");
            console.log("header_hash            = " + header_hash);
            console.log("miner_sent_header_hash = " + miner_given_header);
            console.log("miner_sent_mixhash     = " + miner_given_mixhash);
            console.log("miner_sent_nonce       = " + miner_given_nonce);
            console.log("height                 = " + job.rpcData.height);
            console.log("job.difficulty         = " + job.difficulty);
            console.log("BLOCK.target           = " + job.target_hex);
            console.log('SHARE.target           = ' + target_share_hex);
            console.log('digest                 = ' + body.digest);
            console.log("miner_sent_jobid       = " + miner_given_jobId);
            console.log('job                    = ' + miner_given_jobId);
            console.log('worker                 = ' + workerName);
            console.log('height                 = ' + job.rpcData.height);
            console.log('difficulty             = ' + difficulty);
            console.log('kawpowd_url            = ' + kawpowd_url);
            console.log("********** END INCOMING SHARE FROM WORKER ************");
            if (body.share == false) {
              if (body.block == false) {
                // It didn't meet either requirement.
                callback('kawpow share didn\'t meet job or block difficulty level', false);
                return shareError([20, 'kawpow validation failed']);
              }
            }

	
        // At this point, either share or block is true (or both)
  
            if (body.block == true) {
              // Good block.
              blockHex = job.serializeBlock(new Buffer(header_hash, 'hex'), new Buffer(miner_given_nonce, 'hex'), new Buffer(miner_given_mixhash, 'hex')).toString('hex');
              blockHash = body.digest;
            }
            callback(null, true);
            return;
          });
        });
      },
      function(callback) {
  
          var blockDiffAdjusted = job.difficulty * shareMultiplier
          var shareDiffFixed = undefined;
  
          if (blockHash !== undefined) {
              var headerBigNum = bignum.fromBuffer(blockHash, {endian: 'little', size: 32});
              var shareDiff = diff1 / headerBigNum.toNumber() * shareMultiplier;
              shareDiffFixed = shareDiff.toFixed(8);
          }
          _this.emit('share', {
            job: miner_given_jobId,
            ip: ipAddress,
            port: port,
            worker: workerName,
            height: job.rpcData.height,
            blockReward: job.rpcData.coinbasevalue,
            difficulty: difficulty,
            shareDiff: shareDiffFixed,
            blockDiff: blockDiffAdjusted,
            blockDiffActual: job.difficulty,
            blockHash: blockHash,
            blockHashInvalid: blockHashInvalid
          }, blockHex);
  
          callback_parent({result: true, error: null, blockHash: blockHash});
          callback(null, true);
          return;
      }
      ], function(err, results) {
        if (err != null) {
          emitErrorLog("kawpow verify failed, ERRORS: "+err);
          return;
        }
      });


    } else {

      _this.daemon.cmd('getkawpowhash', [ header_hash, miner_given_mixhash, miner_given_nonce, job.rpcData.height, job.target_hex ], function (results) {

        var digest = results[0].response.digest;
        var result = results[0].response.result;
        var mix_hash = results[0].response.mix_hash;
        var meets_target = results[0].response.meets_target;

        if (result == 'true') {
          // console.log("SHARE IS VALID");
          let headerBigNum = BigInt(result, 32);
          if (job.target.ge(headerBigNum)) {
            // console.log("BLOCK CANDIDATE");
            var blockHex = job.serializeBlock(new Buffer(header_hash, 'hex'), new Buffer(miner_given_nonce, 'hex'), new Buffer(mix_hash, 'hex')).toString('hex');
            var blockHash = digest;
          }
          var blockDiffAdjusted = job.difficulty * shareMultiplier
          var shareDiffFixed = undefined;

          if (blockHash !== undefined) {
              var shareDiff = diff1 / headerBigNum * shareMultiplier;
              shareDiffFixed = shareDiff.toFixed(8);
          }

          _this.emit('share', {
              job: miner_given_jobId,
              ip: ipAddress,
              port: port,
              worker: workerName,
              height: job.rpcData.height,
              blockReward: job.rpcData.coinbasevalue,
              difficulty: difficulty,
              shareDiff: shareDiffFixed,
              blockDiff: blockDiffAdjusted,
              blockDiffActual: job.difficulty,
              blockHash: blockHash,
              blockHashInvalid: blockHashInvalid
          }, blockHex);

          // return {result: true, error: null, blockHash: blockHash};
          // callback_parent( {error: error, result: null});
          callback_parent({result: true, error: null, blockHash: blockHash});

        } else {
          // console.log("SHARE FAILED");
          return shareError([20, 'bad share: invalid hash']);
        }


      });
    }
  }
};
JobManager.prototype.__proto__ = events.EventEmitter.prototype;
