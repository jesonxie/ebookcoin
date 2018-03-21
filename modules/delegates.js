var crypto = require('crypto');
var	extend = require('extend');
var	ed = require('ed25519');
var	async = require('async');
var	shuffle = require('knuth-shuffle').knuthShuffle;
var	Router = require('../helpers/router.js');
var	slots = require('../helpers/slots.js');
var	schedule = require('node-schedule');
var	util = require('util');
var	constants = require('../helpers/constants.js');
var	TransactionTypes = require('../helpers/transaction-types.js');
var	sandboxHelper = require('../helpers/sandbox.js');

require('array.prototype.find'); // Old node fix

// private fields
var modules, library, self, privated = {}, shared = {};

privated.loaded = false;

privated.keypairs = {};
//定义和delegate类型交易相关的处理函数
function Delegate() {
	this.create = function (data, trs) {
		trs.recipientId = null;
		trs.amount = 0;
		trs.asset.delegate = {
			username: data.username || data.sender.username,
			publicKey: data.sender.publicKey
		};

		return trs;
	};

	this.calculateFee = function (trs, sender) {
		return 100 * constants.fixedPoint;//fixedPoint=100000000
	};

	this.verify = function (trs, sender, cb) {
		if (trs.recipientId) {
			return setImmediate(cb, "Invalid recipient");
		}

		if (trs.amount !== 0) {
			return setImmediate(cb, "Invalid transaction amount");
		}

		if (!sender.username) {
			if (!trs.asset.delegate.username) {
				return setImmediate(cb, "Invalid transaction asset");
			}

			var allowSymbols = /^[a-z0-9!@$&_.]+$/g;
			if (!allowSymbols.test(trs.asset.delegate.username.toLowerCase())) {
				return setImmediate(cb, "Username contains invalid characters");
			}

			var isAddress = /^[0-9]+[L|l]$/g;
			if (isAddress.test(trs.asset.delegate.username)) {
				return setImmediate(cb, "Username cannot be a potential address");
			}

			if (trs.asset.delegate.username.length < 1) {
				return setImmediate(cb, "Username is too short. Minimum is 1 character");
			}

			if (trs.asset.delegate.username.length > 20) {
				return setImmediate(cb, "Username is too long. Maximum is 20 characters");
			}
		} else {
			if (trs.asset.delegate.username && trs.asset.delegate.username != sender.username) {
				return cb("Account already has a username");
			}
		}

		if (sender.isDelegate) {
			return cb("Account is already a delegate");
		}

		if (sender.username) {
			return cb(null, trs);
		}

		modules.accounts.getAccount({
			username: trs.asset.delegate.username
		}, function (err, account) {
			if (err) {
				return cb(err);
			}

			if (account) {
				return cb("Username already exists");
			}

			cb(null, trs);
		});
	};

	this.process = function (trs, sender, cb) {
		setImmediate(cb, null, trs);
	};

	this.getBytes = function (trs) {
		if (!trs.asset.delegate.username) {
			return null;
		}
		try {
			var buf = new Buffer(trs.asset.delegate.username, 'utf8');
		} catch (e) {
			throw Error(e.toString());
		}

		return buf;
	};

	this.apply = function (trs, block, sender, cb) {
		var data = {
			address: sender.address,
			u_isDelegate: 0,
			isDelegate: 1,
			vote: 0
		};

		if (!sender.nameexist && trs.asset.delegate.username) {
			data.u_username = null;
			data.username = trs.asset.delegate.username;
		}

		modules.accounts.setAccountAndGet(data, cb);
	};

	this.undo = function (trs, block, sender, cb) {
		var data = {
			address: sender.address,
			u_isDelegate: 1,
			isDelegate: 0,
			vote: 0
		};

		if (!sender.nameexist && trs.asset.delegate.username) {
			data.username = null;
			data.u_username = trs.asset.delegate.username;
		}

		modules.accounts.setAccountAndGet(data, cb);
	};

	this.applyUnconfirmed = function (trs, sender, cb) {
		if (sender.u_username && trs.asset.delegate.username && trs.asset.delegate.username != sender.u_username) {
			return cb("Account already has a username");
		}

		if (sender.u_isDelegate) {
			return cb("Account is already a delegate");
		}

		function done() {
			var data = {
				address: sender.address,
				u_isDelegate: 1,
				isDelegate: 0
			};

			if (!sender.nameexist && trs.asset.delegate.username) {
				data.username = null;
				data.u_username = trs.asset.delegate.username;
			}

			modules.accounts.setAccountAndGet(data, cb);
		}

		if (sender.username) {
			return done();
		}

		modules.accounts.getAccount({
			u_username: trs.asset.delegate.username
		}, function (err, account) {
			if (err) {
				return cb(err);
			}

			if (account) {
				return cb("Username already exists");
			}

			done();
		});
	};

	this.undoUnconfirmed = function (trs, sender, cb) {
		var data = {
			address: sender.address,
			u_isDelegate: 0,
			isDelegate: 0
		};

		if (!sender.nameexist && trs.asset.delegate.username) {
			data.username = null;
			data.u_username = null;
		}

		modules.accounts.setAccountAndGet(data, cb);
	};

	this.objectNormalize = function (trs) {
		var report = library.scheme.validate(trs.asset.delegate, {
			type: "object",
			properties: {
				publicKey: {
					type: "string",
					format: "publicKey"
				}
			},
			required: ["publicKey"]
		});

		if (!report) {
			throw Error("Can't verify delegate transaction, incorrect parameters: " + library.scheme.getLastError());
		}

		return trs;
	};

	this.dbRead = function (raw) {
		if (!raw.d_username) {
			return null;
		} else {
			var delegate = {
				username: raw.d_username,
				publicKey: raw.t_senderPublicKey,
				address: raw.t_senderId
			};

			return {delegate: delegate};
		}
	};

	this.dbSave = function (trs, cb) {
		library.dbLite.query("INSERT INTO delegates(username, transactionId) VALUES($username, $transactionId)", {
			username: trs.asset.delegate.username,
			transactionId: trs.id
		}, cb);
	};

	this.ready = function (trs, sender) {
		if (sender.multisignatures.length) {
			if (!trs.signatures) {
				return false;
			}
			return trs.signatures.length >= sender.multimin - 1;
		} else {
			return true;
		}
	};
}

// Constructor
function Delegates(cb, scope) {
	library = scope;
	self = this;
	self.__private = privated;
	privated.attachApi();

	library.logic.transaction.attachAssetType(TransactionTypes.DELEGATE, new Delegate());

	setImmediate(cb, null, self);
}

// private methods
//绑定这个模块提供的api接口和处理函数(share.xx)
privated.attachApi = function () {
	var router = new Router();

	router.use(function (req, res, next) {
		if (modules && privated.loaded) return next();
		res.status(500).send({success: false, error: "Blockchain is loading"});
	});

	router.map(shared, {
		"get /voters": "getVoters",
		"get /get": "getDelegate",
		"get /": "getDelegates",
		"get /fee": "getFee",
		"get /forging/getForgedByAccount": "getForgedByAccount",
		"put /": "addDelegate"
	});
	//如果是测试状态才能使用下面两个api
	if (process.env.DEBUG) {
		var tmpKepairs = {};

		router.get('/forging/disableAll', function (req, res) {
			if (Object.keys(tmpKepairs).length !== 0) {
				return res.json({success: false});
			}

			tmpKepairs = privated.keypairs;
			privated.keypairs = {};
			return res.json({success: true});
		});

		router.get('/forging/enableAll', function (req, res) {
			if (Object.keys(tmpKepairs).length === 0) {
				return res.json({success: false});
			}

			privated.keypairs = tmpKepairs;
			tmpKepairs = {};
			return res.json({success: true});
		});
	}
	//受委托人访问本节点，并让本节点记录下密钥对，该密钥对在本机生产区块(轮到该受委托人时)时要用来签名区块
	router.post('/forging/enable', function (req, res) {
		var body = req.body;
		library.scheme.validate(body, {
			type: "object",
			properties: {
				secret: {
					type: "string",
					minLength: 1,
					maxLength: 100
				},
				publicKey: {
					type: "string",
					format: "publicKey"
				}
			},
			required: ["secret"]
		}, function (err) {
			if (err) {
				return res.json({success: false, error: err[0].message});
			}

			var ip = req.connection.remoteAddress;
			//如果受委托人访问时使用的电脑的IP不在本节点的forging.access白名单，则拒绝访问。每个节点初始forging.access白名单只有本机地址127.0.0.1
			//只有满足两种情况才允许：1.受委托人在自己的电脑运行整套程序，再通过浏览器访问该API提交密钥对
			//2.A电脑(节点)运行整套程序，受委托人用B电脑(节点)去访问A的api，而且A电脑(节点)已经将B电脑(节点)的IP地址写进白名单，需要受委托人对A节点信任
			if (library.config.forging.access.whiteList.length > 0 && library.config.forging.access.whiteList.indexOf(ip) < 0) {
				return res.json({success: false, error: "Access denied"});
			}

			var keypair = ed.MakeKeypair(crypto.createHash('sha256').update(body.secret, 'utf8').digest());

			if (body.publicKey) {
				if (keypair.publicKey.toString('hex') != body.publicKey) {
					return res.json({success: false, error: "Invalid passphrase"});
				}
			}

			if (privated.keypairs[keypair.publicKey.toString('hex')]) {
				return res.json({success: false, error: "Forging is already enabled"});
			}

			modules.accounts.getAccount({publicKey: keypair.publicKey.toString('hex')}, function (err, account) {
				if (err) {
					return res.json({success: false, error: err.toString()});
				}
				if (account && account.isDelegate) {
					privated.keypairs[keypair.publicKey.toString('hex')] = keypair;
					return res.json({success: true, address: account.address});
					library.logger.info("Forging enabled on account: " + account.address);
				} else {
					return res.json({success: false, error: "Delegate not found"});
				}
			});
		});
	});
	//与上一个函数相似，区别仅在于请求删除本节点所保存的密钥对
	router.post('/forging/disable', function (req, res) {
		var body = req.body;
		library.scheme.validate(body, {
			type: "object",
			properties: {
				secret: {
					type: "string",
					minLength: 1,
					maxLength: 100
				},
				publicKey: {
					type: "string",
					format: "publicKey"
				}
			},
			required: ["secret"]
		}, function (err) {
			if (err) {
				return res.json({success: false, error: err[0].message});
			}

			var ip = req.connection.remoteAddress;

			if (library.config.forging.access.whiteList.length > 0 && library.config.forging.access.whiteList.indexOf(ip) < 0) {
				return res.json({success: false, error: "Access denied"});
			}

			var keypair = ed.MakeKeypair(crypto.createHash('sha256').update(body.secret, 'utf8').digest());

			if (body.publicKey) {
				if (keypair.publicKey.toString('hex') != body.publicKey) {
					return res.json({success: false, error: "Invalid passphrase"});
				}
			}

			if (!privated.keypairs[keypair.publicKey.toString('hex')]) {
				return res.json({success: false, error: "Delegate not found"});
			}

			modules.accounts.getAccount({publicKey: keypair.publicKey.toString('hex')}, function (err, account) {
				if (err) {
					return res.json({success: false, error: err.toString()});
				}
				if (account && account.isDelegate) {
					delete privated.keypairs[keypair.publicKey.toString('hex')];
					return res.json({success: true, address: account.address});
					library.logger.info("Forging disabled on account: " + account.address); //fixme
				} else {
					return res.json({success: false, error: "Delegate not found"});
				}
			});
		});
	});

	router.get('/forging/status', function (req, res) {
		var query = req.query;
		library.scheme.validate(query, {
			type: "object",
			properties: {
				publicKey: {
					type: "string",
					format: "publicKey"
				}
			},
			required: ["publicKey"]
		}, function (err) {
			if (err) {
				return res.json({success: false, error: err[0].message});
			}

			return res.json({success: true, enabled: !!privated.keypairs[query.publicKey]});
		});
	});

	/*router.map(privated, {
	 "post /forging/enable": "enableForging",
	 "post /forging/disable": "disableForging",
	 "get /forging/status": "statusForging"
	 });*/

	library.network.app.use('/api/delegates', router);
	library.network.app.use(function (err, req, res, next) {
		if (!err) return next();
		library.logger.error(req.url, err.toString());
		res.status(500).send({success: false, error: err.toString()});
	});
};
//从men_account表中查找出获得票数前101位的受委托人，返回他们的publickey
privated.getKeysSortByVote = function (cb) {
	modules.accounts.getAccounts({
		isDelegate: 1,
		sort: {"vote": -1, "publicKey": 1},
		limit: constants.delegates
	}, ["publicKey"], function (err, rows) {
		if (err) {
			cb(err);
		}
		cb(null, rows.map(function (el) {
			return el.publicKey;
		}));
	});
};
//根据块高度获得块时段数据，为区块提供了生产该区块的受委托人的密钥对和时间戳
privated.getBlockSlotData = function (slot, height, cb) {
	//根据当前块高度获得可以生产区块的受托人列表，找到激活的受托人标识，继而找到对应的密钥对
	self.generateDelegateList(height, function (err, activeDelegates) {
		if (err) {
			return cb(err);
		}
		var currentSlot = slot;
		var lastSlot = slots.getLastSlot(currentSlot);//获得currentslot所在轮round的最大的slot

		for (; currentSlot < lastSlot; currentSlot += 1) {
			var delegate_pos = currentSlot % constants.delegates;

			var delegate_id = activeDelegates[delegate_pos];

			if (delegate_id && privated.keypairs[delegate_id]) {
				return cb(null, {time: slots.getSlotTime(currentSlot), keypair: privated.keypairs[delegate_id]});
			}
		}
		cb(null, null);
	});
};

//产生区块的入口
privated.loop = function (cb) {
	if (!Object.keys(privated.keypairs).length) {
		library.logger.debug('Loop', 'exit: no delegates');
		return setImmediate(cb);
	}

	if (!privated.loaded || modules.loader.syncing() || !modules.round.loaded()) {
		// library.logger.log('Loop', 'exit: syncing');
		return setImmediate(cb);
	}
	//判断时间戳等是否正确
	var currentSlot = slots.getSlotNumber();
	var lastBlock = modules.blocks.getLastBlock();

	if (currentSlot == slots.getSlotNumber(lastBlock.timestamp)) {
		// library.logger.log('Loop', 'exit: lastBlock is in the same slot');
		return setImmediate(cb);
	}
	//获得块时段数据，为区块提供了密钥对和时间戳
	privated.getBlockSlotData(currentSlot, lastBlock.height + 1, function (err, currentBlockData) {
		if (err || currentBlockData === null) {
			library.logger.log('Loop', 'skiping slot');
			return setImmediate(cb);
		}

		library.sequence.add(function (cb) {
			if (slots.getSlotNumber(currentBlockData.time) == slots.getSlotNumber()) {
				//产生新的块
				modules.blocks.generateBlock(currentBlockData.keypair, currentBlockData.time, function (err) {
					library.logger.log('Round ' + modules.round.calc(modules.blocks.getLastBlock().height) + ' new block id: ' + modules.blocks.getLastBlock().id + ' height: ' + modules.blocks.getLastBlock().height + ' slot: ' + slots.getSlotNumber(currentBlockData.time) + ' reward: ' + modules.blocks.getLastBlock().reward);
					cb(err);
				});
			} else {
				// library.logger.log('Loop', 'exit: ' + _activeDelegates[slots.getSlotNumber() % constants.delegates] + ' delegate slot');
				setImmediate(cb);
			}
		}, function (err) {
			if (err) {
				library.logger.error("Failed to get block slot data", err);
			}
			setImmediate(cb);
		});
	});
};
//只在初始化时调用，加载最初的101位受委托人
privated.loadMyDelegates = function (cb) {
	var secrets = null;
	if (library.config.forging.secret) {//取出最初的101位受委托人的密码
		secrets = util.isArray(library.config.forging.secret) ? library.config.forging.secret : [library.config.forging.secret];
	}

	async.eachSeries(secrets, function (secret, cb) {
		var keypair = ed.MakeKeypair(crypto.createHash('sha256').update(secret, 'utf8').digest());

		modules.accounts.getAccount({//根据这些受委托人的密钥对获取账户信息
			publicKey: keypair.publicKey.toString('hex')
		}, function (err, account) {
			if (err) {
				return cb(err);
			}

			if (!account) {
				return cb("Account " + keypair.publicKey.toString('hex') + " not found");
			}

			if (account.isDelegate) {
				privated.keypairs[keypair.publicKey.toString('hex')] = keypair;
				library.logger.info("Forging enabled on account: " + account.address);
			} else {
				library.logger.info("Delegate with this public key not found: " + keypair.publicKey.toString('hex'));
			}
			cb();
		});
	}, cb);
};

// Public methods
//根据区块高度得到该轮可以生产区块的受托人列表
Delegates.prototype.generateDelegateList = function (height, cb) {
	privated.getKeysSortByVote(function (err, truncDelegateList) {
		if (err) {
			return cb(err);
		}
		var seedSource = modules.round.calc(height).toString();

		var currentSeed = crypto.createHash('sha256').update(seedSource, 'utf8').digest();
		for (var i = 0, delCount = truncDelegateList.length; i < delCount; i++) {
			for (var x = 0; x < 4 && i < delCount; i++, x++) {
				var newIndex = currentSeed[x] % delCount;
				var b = truncDelegateList[newIndex];
				truncDelegateList[newIndex] = truncDelegateList[i];
				truncDelegateList[i] = b;
			}
			currentSeed = crypto.createHash('sha256').update(currentSeed).digest();
		}
		//在该轮那个时间戳slot由哪个受委托人生产区块按照truncDelegateList数组的顺序定好
		cb(null, truncDelegateList);
	});

};
//验证用户投票（vote型交易），publickey为用户的公钥，votes包含投票给某一位受委托人(公钥)和取消对某一位受委托人(公钥)的投票
//在投票交易写入区块时调用
Delegates.prototype.checkDelegates = function (publicKey, votes, cb) {
	if (util.isArray(votes)) {
		modules.accounts.getAccount({publicKey: publicKey}, function (err, account) {//先验证投票者用户是否存在
			if (err) {
				return cb(err);
			}
			if (!account) {
				return cb("Account not found");
			}

			async.eachSeries(votes, function (action, cb) {//对votes里每一个投票和取消投票验证
				var math = action[0];

				if (math !== '+' && math !== '-') {
					return cb("Invalid math operator");
				}

				var publicKey = action.slice(1);

				try {
					new Buffer(publicKey, "hex");
				} catch (e) {
					return cb("Invalid public key");
				}
				//account.delegates里包含该用户对哪些受委托人投票了
				if (math == "+" && (account.delegates !== null && account.delegates.indexOf(publicKey) != -1)) {
					return cb("Failed to add vote, account has already voted for this delegate");
				}
				if (math == "-" && (account.delegates === null || account.delegates.indexOf(publicKey) === -1)) {
					return cb("Failed to remove vote, account has not voted for this delegate");
				}
				//检查受委托人账户是否存在
				modules.accounts.getAccount({publicKey: publicKey, isDelegate: 1}, function (err, account) {
					if (err) {
						return cb(err);
					}

					if (!account) {
						return cb("Delegate not found");
					}

					cb();
				});
			}, cb);
		});
	} else {
		setImmediate(cb, "Please provide an array of votes");
	}
};
//和checkDelegates函数的功能一样，区别在于这里检查的事men_account表的带有u_前缀的列：u_deligates,前者检查deligates列
//在处理投票交易(processtraction)时调用
Delegates.prototype.checkUnconfirmedDelegates = function (publicKey, votes, cb) {
	if (util.isArray(votes)) {
		modules.accounts.getAccount({publicKey: publicKey}, function (err, account) {//先验证投票者用户是否存在
			if (err) {
				return cb(err);
			}
			if (!account) {
				return cb("Account not found");
			}

			async.eachSeries(votes, function (action, cb) {//对votes里每一个投票和取消投票验证
				var math = action[0];

				if (math !== '+' && math !== '-') {
					return cb("Invalid math operator");
				}

				var publicKey = action.slice(1);


				try {
					new Buffer(publicKey, "hex");
				} catch (e) {
					return cb("Invalid public key");
				}
				//account.u_delegates里包含该用户对哪些受委托人投票了
				if (math == "+" && (account.u_delegates !== null && account.u_delegates.indexOf(publicKey) != -1)) {
					return cb("Failed to add vote, account has already voted for this delegate");
				}
				if (math == "-" && (account.u_delegates === null || account.u_delegates.indexOf(publicKey) === -1)) {
					return cb("Failed to remove vote, account has not voted for this delegate");
				}
				//检查受委托人账户是否存在
				modules.accounts.getAccount({publicKey: publicKey, isDelegate: 1}, function (err, account) {
					if (err) {
						return cb(err);
					}

					if (!account) {
						return cb("Delegate not found");
					}

					cb();
				});
			}, cb);
		});
	} else {
		return setImmediate(cb, "Please provide an array of votes");
	}
};
//产生分叉块，cause是产生的原因，有四种。在处理新块,加载区块链后本地验证区块和从其他节点更新区块时调用（processBlock()）
Delegates.prototype.fork = function (block, cause) {
	library.logger.info('Fork', {
		delegate: block.generatorPublicKey,
		block: {id: block.id, timestamp: block.timestamp, height: block.height, previousBlock: block.previousBlock},
		cause: cause
	});
	//将分叉块存入fork_stat表
	library.dbLite.query("INSERT INTO forks_stat (delegatePublicKey, blockTimestamp, blockId, blockHeight, previousBlock, cause) " +
		"VALUES ($delegatePublicKey, $blockTimestamp, $blockId, $blockHeight, $previousBlock, $cause);", {
		delegatePublicKey: block.generatorPublicKey,
		blockTimestamp: block.timestamp,
		blockId: block.id,
		blockHeight: block.height,
		previousBlock: block.previousBlock,
		cause: cause
	});
};
//验证块时间戳slot对应的产出区块的受委托人和实际的块生产者是否一致
Delegates.prototype.validateBlockSlot = function (block, cb) {
	self.generateDelegateList(block.height, function (err, activeDelegates) {
		if (err) {
			return cb(err);
		}
		var currentSlot = slots.getSlotNumber(block.timestamp);
		var delegate_id = activeDelegates[currentSlot % constants.delegates];

		if (delegate_id && block.generatorPublicKey == delegate_id) {
			return cb();
		} else {
			library.logger.error("Expected generator: " + delegate_id + " Received generator: " + block.generatorPublicKey);
			return cb("Failed to verify slot: " + currentSlot);
		}
	});
};

Delegates.prototype.sandboxApi = function (call, args, cb) {
	sandboxHelper.callMethod(shared, call, args, cb);
};

// Events
//在app.js初始化后出发bind事件，这里监听到bind事件就执行
Delegates.prototype.onBind = function (scope) {
	modules = scope;
};
//区块链加载并验证结束后触发此方法，可以开始产生新区块
Delegates.prototype.onBlockchainReady = function () {
	privated.loaded = true;

	privated.loadMyDelegates(function nextLoop(err) {
		if (err) {
			library.logger.error("Failed to load delegates", err);
		}
		//产生新区块入口
		privated.loop(function () {
			setTimeout(nextLoop, 1000);//至少一秒后才能又进入loop函数，也即是产生新块
		});

	});
};

Delegates.prototype.cleanup = function (cb) {
	privated.loaded = false;
	cb();
};

// Shared
shared.getDelegate = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			transactionId: {
				type: "string"
			},
			publicKey: {
				type: "string"
			},
			username: {
				type: "string"
			}
		}
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		modules.accounts.getAccounts({
			isDelegate: 1,
			sort: {"vote": -1, "publicKey": 1}
		}, ["username", "address", "publicKey", "vote", "missedblocks", "producedblocks", "virgin"], function (err, delegates) {
			if (err) {
				return cb(err.toString());
			}

			var limit = query.limit || 101,
				offset = query.offset || 0,
				orderField = query.orderBy,
				active = query.active;

			orderField = orderField ? orderField.split(':') : null;
			limit = limit > 101 ? 101 : limit;
			var orderBy = orderField ? orderField[0] : null;
			var sortMode = orderField && orderField.length == 2 ? orderField[1] : 'asc';
			var count = delegates.length;
			var length = Math.min(limit, count);
			var realLimit = Math.min(offset + limit, count);

			for (var i = 0; i < delegates.length; i++) {
				delegates[i].rate = i + 1;

				var percent = 100 - (delegates[i].missedblocks / ((delegates[i].producedblocks + delegates[i].missedblocks) / 100));
				percent = percent || 0;
				var outsider = i + 1 > constants.delegates && delegates[i].virgin;
				delegates[i].productivity = !outsider ? delegates[i].virgin ? 0 : parseFloat(Math.floor(percent * 100) / 100).toFixed(2) : null;
			}

			var delegate = delegates.find(function (delegate) {
				if (query.transactionId) {
					// TODO: Store transactionId
				}
				if (query.publicKey) {
					return delegate.publicKey == query.publicKey;
				}
				if (query.username) {
					return delegate.username == query.username;
				}

				return false;
			});

			if (delegate) {
				cb(null, {delegate: delegate});
			} else {
				cb("Delegate not found");
			}
		});
	});
};

shared.getVoters = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: 'object',
		properties: {
			publicKey: {
				type: "string",
				format: "publicKey"
			}
		},
		required: ['publicKey']
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		library.dbLite.query("select GROUP_CONCAT(accountId) from mem_accounts2delegates where dependentId = $publicKey", {
			publicKey: query.publicKey
		}, ['accountId'], function (err, rows) {
			if (err) {
				library.logger.error(err);
				return cb("Database error");
			}

			var addresses = rows[0].accountId.split(',');

			modules.accounts.getAccounts({
				address: {$in: addresses},
				sort: 'balance'
			}, ['address', 'balance'], function (err, rows) {
				if (err) {
					library.logger.error(err);
					return cb("Database error");
				}

				return cb(null, {accounts: rows});
			});
		});
	});
};

shared.getDelegates = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: 'object',
		properties: {
			limit: {
				type: "integer",
				minimum: 0,
				maximum: 101
			},
			offset: {
				type: "integer",
				minimum: 0
			},
			orderBy: {
				type: "string"
			}
		}
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		modules.accounts.getAccounts({
			isDelegate: 1,
			// limit: query.limit > 101 ? 101 : query.limit,
			// offset: query.offset,
			sort: {"vote": -1, "publicKey": 1}
		}, ["username", "address", "publicKey", "vote", "missedblocks", "producedblocks", "virgin"], function (err, delegates) {
			if (err) {
				return cb(err.toString());
			}

			var limit = query.limit || 101,
				offset = query.offset || 0,
				orderField = query.orderBy,
				active = query.active;

			orderField = orderField ? orderField.split(':') : null;
			limit = limit > 101 ? 101 : limit;
			var orderBy = orderField ? orderField[0] : null;
			var sortMode = orderField && orderField.length == 2 ? orderField[1] : 'asc';
			var count = delegates.length;
			var length = Math.min(limit, count);
			var realLimit = Math.min(offset + limit, count);

			for (var i = 0; i < delegates.length; i++) {
				delegates[i].rate = i + 1;

				var percent = 100 - (delegates[i].missedblocks / ((delegates[i].producedblocks + delegates[i].missedblocks) / 100));
				percent = percent || 0;
				var outsider = i + 1 > constants.delegates && delegates[i].virgin;
				delegates[i].productivity = !outsider ? delegates[i].virgin ? 0 : parseFloat(Math.floor(percent * 100) / 100).toFixed(2) : null;
			}

			delegates.sort(function compare(a, b) {
				if (sortMode == 'asc') {
					if (a[orderBy] < b[orderBy])
						return -1;
					if (a[orderBy] > b[orderBy])
						return 1;
				} else if (sortMode == 'desc') {
					if (a[orderBy] > b[orderBy])
						return -1;
					if (a[orderBy] < b[orderBy])
						return 1;
				}
				return 0;
			});

			var result = delegates.slice(offset, realLimit);

			cb(null, {delegates: result, totalCount: count});
		});
	});
};

shared.getFee = function (req, cb) {
	var query = req.body;
	var fee = null;

	fee = 100 * constants.fixedPoint;

	cb(null, {fee: fee});
};

shared.getForgedByAccount = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			generatorPublicKey: {
				type: "string",
				format: "publicKey"
			}
		},
		required: ["generatorPublicKey"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		modules.accounts.getAccount({publicKey: query.generatorPublicKey}, ["fees", "rewards"], function (err, account) {
			if (err || !account) {
				return cb(err || "Account not found");
			}
			cb(null, {fees: account.fees, rewards: account.rewards, forged: account.fees + account.rewards});
		});
	});
};

privated.enableForging = function (req, cb) {

};

privated.disableForging = function (req, cb) {

};

privated.statusForging = function (req, cb) {

};

/**
 * @apiGroup Delegate
 * @apiName addDelegate
 *
 * @api {PUT} /api/delegates
 * @apiVersion 0.1.3
 *
 * @apiParam {String} secret Secret key of account.
 * @apiSuccess {Object} transaction A transaction object.
 *
 * @apiParamExample {json} Request(Example)
 *
 * {
 *     "secret" : "Secret key of account",
 *     "secondSecret": "Second secret of account",
 *     "username" : "Username of delegate. String from 1 to 20 characters."
 * }
 *
 * @apiSuccessExample {json} Response(Example)
 * {
 *     "success": true,
 *     "transaction": "transaction object"
 * }
 */
shared.addDelegate = function (req, cb) {
	var body = req.body;
	library.scheme.validate(body, {
		type: "object",
		properties: {
			secret: {
				type: "string",
				minLength: 1,
				maxLength: 100
			},
			publicKey: {
				type: "string",
				format: "publicKey"
			},
			secondSecret: {
				type: "string",
				minLength: 1,
				maxLength: 100
			},
			username: {
				type: "string"
			}
		},
		required: ["secret"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		var hash = crypto.createHash('sha256').update(body.secret, 'utf8').digest();
		var keypair = ed.MakeKeypair(hash);

		if (body.publicKey) {
			if (keypair.publicKey.toString('hex') != body.publicKey) {
				return cb("Invalid passphrase");
			}
		}

		library.balancesSequence.add(function (cb) {
			if (body.multisigAccountPublicKey && body.multisigAccountPublicKey != keypair.publicKey.toString('hex')) {
				modules.accounts.getAccount({publicKey: body.multisigAccountPublicKey}, function (err, account) {
					if (err) {
						return cb(err.toString());
					}

					if (!account || !account.publicKey) {
						return cb("Multisignature account not found");
					}

					if (!account.multisignatures || !account.multisignatures) {
						return cb("Account does not have multisignatures enabled");
					}

					if (account.multisignatures.indexOf(keypair.publicKey.toString('hex')) < 0) {
						return cb("Account does not belong to multisignature group");
					}

					modules.accounts.getAccount({publicKey: keypair.publicKey}, function (err, requester) {
						if (err) {
							return cb(err.toString());
						}

						if (!requester || !requester.publicKey) {
							return cb("Invalid requester");
						}

						if (requester.secondSignature && !body.secondSecret) {
							return cb("Invalid second passphrase");
						}

						if (requester.publicKey == account.publicKey) {
							return cb("Incorrect requester");
						}

						var secondKeypair = null;

						if (requester.secondSignature) {
							var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
							secondKeypair = ed.MakeKeypair(secondHash);
						}

						try {
							var transaction = library.logic.transaction.create({
								type: TransactionTypes.DELEGATE,
								username: body.username,
								sender: account,
								keypair: keypair,
								secondKeypair: secondKeypair,
								requester: keypair
							});
						} catch (e) {
							return cb(e.toString());
						}
						modules.transactions.receiveTransactions([transaction], cb);
					});
				});
			} else {
				modules.accounts.getAccount({publicKey: keypair.publicKey.toString('hex')}, function (err, account) {
					if (err) {
						return cb(err.toString());
					}

					if (!account || !account.publicKey) {
						return cb("Invalid account");
					}

					if (account.secondSignature && !body.secondSecret) {
						return cb("Invalid second passphrase");
					}

					var secondKeypair = null;

					if (account.secondSignature) {
						var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
						secondKeypair = ed.MakeKeypair(secondHash);
					}

					try {
						var transaction = library.logic.transaction.create({
							type: TransactionTypes.DELEGATE,
							username: body.username,
							sender: account,
							keypair: keypair,
							secondKeypair: secondKeypair
						});
					} catch (e) {
						return cb(e.toString());
					}
					modules.transactions.receiveTransactions([transaction], cb);
				});
			}
		}, function (err, transaction) {
			if (err) {
				return cb(err.toString());
			}

			cb(null, {transaction: transaction[0]});
		});
	});
};

// Export
module.exports = Delegates;
