var async = require('async'),
	util = require('util'),
	ip = require('ip'),
	Router = require('../helpers/router.js'),
	extend = require('extend'),
	fs = require('fs'),
	path = require('path'),
	sandboxHelper = require('../helpers/sandbox.js');

require('array.prototype.find'); // Old node fix

// private fields
var modules, library, self, privated = {}, shared = {};

// Constructor
function Peer(cb, scope) {
	library = scope;
	self = this;
	self.__private = privated;
	privated.attachApi();

	setImmediate(cb, null, self);
}

// private methods
//绑定这个模块提供的api接口和处理函数(share.xx)，注意和transport.js模块的api接口路径的区别，后者为/peer/xx,这里是/api/peers/xx
privated.attachApi = function () {
	var router = new Router();

	router.use(function (req, res, next) {
		if (modules) return next();
		res.status(500).send({success: false, error: "Blockchain is loading"});
	});

	router.map(shared, {
		"get /": "getPeers",
		"get /version": "version",
		"get /get": "getPeer"
	});

	router.use(function (req, res) {
		res.status(500).send({success: false, error: "API endpoint not found"});
	});

	library.network.app.use('/api/peers', router);//定义父路径
	library.network.app.use(function (err, req, res, next) {
		if (!err) return next();
		library.logger.error(req.url, err.toString());
		res.status(500).send({success: false, error: err.toString()});
	});
};
//通过访问其他节点获取节点列表来更新本地节点表
privated.updatePeerList = function (cb) {
	//在本地节点表随机找一个节点，然后访问该节点的api:/peer/list,获取其节点列表
	modules.transport.getFromRandomPeer({
		api: '/list',
		method: 'GET'
	}, function (err, data) {
		if (err) {
			return cb();
		}
		
		var report = library.scheme.validate(data.body.peers, {type: "array", required: true, uniqueItems: true});
		//先验证返回的列表数据是否包含某些必要字段
		library.scheme.validate(data.body, {
			type: "object",
			properties: {
				peers: {
					type: "array",
					uniqueItems: true
				}
			},
			required: ['peers']
		}, function (err) {
			if (err) {
				return cb();
			}

			var peers = data.body.peers;
			//再逐个验证请求得到的节点列表中的各个节点
			async.eachLimit(peers, 2, function (peer, cb) {
				library.scheme.validate(peer, {
					type: "object",
					properties: {
						ip: {
							type: "string"
						},
						port: {
							type: "integer",
							minimum: 1,
							maximum: 65535
						},
						state: {
							type: "integer",
							minimum: 0,
							maximum: 3
						},
						os: {
							type: "string"
						},
						sharePort: {
							type: "integer",
							minimum: 0,
							maximum: 1
						},
						version: {
							type: "string"
						}
					},
					required: ['ip', 'port', 'state']
				}, function (err) {
					if (err) {
						console.log(err, peer);
						return setImmediate(cb, "Invalid peer: " + err);
					}

					peer.ip = parseInt(peer.ip);

					if (isNaN(peer.ip)) {
						return setImmediate(cb);
					}

					if (ip.toLong("127.0.0.1") === peer.ip || peer.port === 0 || peer.port > 65535) {
						return setImmediate(cb);
					}
					//验证通过就更新本地peers表
					self.update(peer, cb);
				});
			}, cb);
		});
	});
};
//查出本地peers表总共有多少个peer
privated.count = function (cb) {
	library.dbLite.query("select count(*) from peers", {"count": Number}, function (err, rows) {
		if (err) {
			library.logger.error('Peer#count', err);
			return cb(err);
		}
		var res = rows.length && rows[0].count;
		cb(null, res);
	});
};
//更改state和clock字段，主要是将禁止的状态state=0，修改为1
privated.banManager = function (cb) {
	library.dbLite.query("UPDATE peers SET state = 1, clock = null where (state = 0 and clock - $now < 0)", {now: Date.now()}, cb);
};

privated.getByFilter = function (filter, cb) {
	var sortFields = ["ip", "port", "state", "os", "sharePort", "version"];
	var sortMethod = '', sortBy = '';
	var limit = filter.limit || null;
	var offset = filter.offset || null;
	delete filter.limit;
	delete filter.offset;

	var where = [];
	var params = {};

	if (filter.hasOwnProperty('state') && filter.state !== null) {
		where.push("state = $state");
		params.state = filter.state;
	}

	if (filter.hasOwnProperty('os') && filter.os !== null) {
		where.push("os = $os");
		params.os = filter.os;
	}

	if (filter.hasOwnProperty('version') && filter.version !== null) {
		where.push("version = $version");
		params.version = filter.version;
	}

	if (filter.hasOwnProperty('shared') && filter.shared !== null) {
		where.push("sharePort = $sharePort");
		params.sharePort = filter.shared;
	}

	if (filter.hasOwnProperty('ip') && filter.ip !== null) {
		where.push("ip = $ip");
		params.ip = filter.ip;
	}

	if (filter.hasOwnProperty('port') && filter.port !== null) {
		where.push("port = $port");
		params.port = filter.port;
	}

	if (filter.hasOwnProperty('orderBy')) {
		var sort = filter.orderBy.split(':');
		sortBy = sort[0].replace(/[^\w\s]/gi, '');
		if (sort.length == 2) {
			sortMethod = sort[1] == 'desc' ? 'desc' : 'asc';
		} else {
			sortMethod = 'desc';
		}
	}

	if (sortBy) {
		if (sortFields.indexOf(sortBy) < 0) {
			return cb("Invalid sort field");
		}
	}

	if (limit !== null) {
		if (limit > 100) {
			return cb("Invalid limit. Maximum is 100");
		}
		params.limit = limit;
	}

	if (offset !== null) {
		params.offset = offset;
	}

	library.dbLite.query("select ip, port, state, os, sharePort, version from peers" +
		(where.length ? (' where ' + where.join(' and ')) : '') +
		(sortBy ? ' order by ' + sortBy + ' ' + sortMethod : '') + " " +
		(limit ? ' limit $limit' : '') +
		(offset ? ' offset $offset ' : ''),
		params, {
			"ip": String,
			"port": Number,
			"state": Number,
			"os": String,
			"sharePort": Number,
			"version": String
		}, function (err, rows) {
			cb(err, rows);
		});
};

// Public methods
Peer.prototype.list = function (options, cb) {
	options.limit = options.limit || 100;

	library.dbLite.query("select p.ip, p.port, p.state, p.os, p.sharePort, p.version from peers p " + (options.dappid ? " inner join peers_dapp pd on p.id = pd.peerId and pd.dappid = $dappid " : "") + " where p.state > 0 and p.sharePort = 1 ORDER BY RANDOM() LIMIT $limit", options, {
		"ip": String,
		"port": Number,
		"state": Number,
		"os": String,
		"sharePort": Number,
		"version": String
	}, function (err, rows) {
		cb(err, rows);
	});
};
//更新本地peers表中节点的状态
Peer.prototype.state = function (pip, port, state, timeoutSeconds, cb) {
	var isFrozenList = library.config.peers.list.find(function (peer) {
		return peer.ip == ip.fromLong(pip) && peer.port == port;
	});//如果在初始配置的节点表(相当于白名单)里找到该节点，则立即返回不用更新
	if (isFrozenList !== undefined) return cb && cb("Peer in white list");
	if (state == 0) {//如果是更新为禁止状态，计算禁止时间
		var clock = (timeoutSeconds || 1) * 1000;
		clock = Date.now() + clock;
	} else {
		clock = null;
	}
	library.dbLite.query("UPDATE peers SET state = $state, clock = $clock WHERE ip = $ip and port = $port;", {
		state: state,
		clock: clock,
		ip: pip,
		port: port
	}, function (err) {
		err && library.logger.error('Peer#state', err);

		cb && cb();
	});
};
//从本地peers表中删除该坏节点
Peer.prototype.remove = function (pip, port, cb) {
	var isFrozenList = library.config.peers.list.find(function (peer) {
		return peer.ip == ip.fromLong(pip) && peer.port == port;
	});//如果在初始配置的节点表(相当于白名单)里找到该节点，则立即返回不能删除
	if (isFrozenList !== undefined) return cb && cb("Peer in white list");
	library.dbLite.query("DELETE FROM peers WHERE ip = $ip and port = $port;", {
		ip: pip,
		port: port
	}, function (err) {
		err && library.logger.error('Peer#delete', err);

		cb && cb(err);
	});
};

Peer.prototype.addDapp = function (config, cb) {
	library.dbLite.query("SELECT id from peers where ip = $ip and port = $port", {
		ip: config.ip,
		port: config.port
	}, ["id"], function (err, data) {
		if (err) {
			return cb(err);
		}
		if (!data.length) {
			return cb();
		}
		var peerId = data[0].id;

		library.dbLite.query("INSERT OR IGNORE INTO peers_dapp (peerId, dappId) VALUES ($peerId, $dappId);", {
			dappId: config.dappid,
			peerId: peerId
		}, cb);
	});
};
//更新本地peers表中调用函数传入的一个peer的信息，或者插入
Peer.prototype.update = function (peer, cb) {
	var dappid = peer.dappid;
	var params = {
		ip: peer.ip,
		port: peer.port,
		os: peer.os || null,
		sharePort: peer.sharePort,
		version: peer.version || null
	};
	async.series([
		function (cb) {//不存在该peer就插入，存在的话这条语句什么都不做
			library.dbLite.query("INSERT OR IGNORE INTO peers (ip, port, state, os, sharePort, version) VALUES ($ip, $port, $state, $os, $sharePort, $version);", extend({}, params, {state: 1}), cb);
		},
		function (cb) {
			if (peer.state !== undefined) {
				params.state = peer.state;
			}//更新该peer的信息
			library.dbLite.query("UPDATE peers SET os = $os, sharePort = $sharePort, version = $version" + (peer.state !== undefined ? ", state = CASE WHEN state = 0 THEN state ELSE $state END " : "") + " WHERE ip = $ip and port = $port;", params, cb);
		},
		function (cb) {
			if (dappid) {//如果有侧链运用，同时更新侧链
				self.addDapp({dappid: dappid, ip: peer.ip, port: peer.port}, cb);
			} else {
				setImmediate(cb);
			}

		}
	], function (err) {
		err && library.logger.error('Peer#update', err);
		cb && cb();
	});
};

Peer.prototype.sandboxApi = function (call, args, cb) {
	sandboxHelper.callMethod(shared, call, args, cb);
};

// Events
Peer.prototype.onBind = function (scope) {
	modules = scope;
};
//在区块链加载结束后触发，依次将配置的节点写入数据库，如果数据库已经存在相同的记录就忽略，然后更新节点列表，触发节点加载完毕事件。
Peer.prototype.onBlockchainReady = function () {//library.config.peers.list配置了初始节点
	async.eachSeries(library.config.peers.list, function (peer, cb) {
		library.dbLite.query("INSERT OR IGNORE INTO peers(ip, port, state, sharePort) VALUES($ip, $port, $state, $sharePort)", {
			ip: ip.toLong(peer.ip),
			port: peer.port,
			state: 2,//初始状态为2，都是健康的节点
			sharePort: Number(true)
		}, cb);
	}, function (err) {
		if (err) {
			library.logger.error('onBlockchainReady', err);
		}
		//查出本地peers表总共有多少个peer（当前只有初始配置的节点）
		privated.count(function (err, count) {
			if (count) {
				privated.updatePeerList(function (err) {//通过访问其他节点的节点列表来更新本地节点列表
					err && library.logger.error('updatePeerList', err);
					library.bus.message('peerReady');//触发节点加载完毕事件
				});
				library.logger.info('Peers ready, stored ' + count);
			} else {
				library.logger.warn('Peers list is empty');
			}
		});
	});
};
//在节点加载完毕后触发
Peer.prototype.onPeerReady = function () {
	setImmediate(function nextUpdatePeerList() {//循环更新节点列表
		privated.updatePeerList(function (err) {
			err && library.logger.error('updatePeerList timer', err);
			setTimeout(nextUpdatePeerList, 60 * 1000);
		})
	});

	setImmediate(function nextBanManager() {//循环更新节点状态
		privated.banManager(function (err) {//如果禁止时间到了，将禁止的状态state=0，修改为1
			err && library.logger.error('banManager timer', err);
			setTimeout(nextBanManager, 65 * 1000)
		});
	});
};

// Shared
shared.getPeers = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			state: {
				type: "integer",
				minimum: 0,
				maximum: 3
			},
			os: {
				type: "string"
			},
			version: {
				type: "string"
			},
			limit: {
				type: "integer",
				minimum: 0,
				maximum: 100
			},
			shared: {
				type: "integer",
				minimum: 0,
				maximum: 1
			},
			orderBy: {
				type: "string"
			},
			offset: {
				type: "integer",
				minimum: 0
			},
			port: {
				type: "integer",
				minimum: 1,
				maximum: 65535
			}
		}
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		if (query.limit < 0 || query.limit > 100) {
			return cb("Invalid limit. Maximum is 100");
		}

		privated.getByFilter(query, function (err, peers) {
			if (err) {
				return cb("Peer not found");
			}

			for (var i = 0; i < peers.length; i++) {
				peers[i].ip = ip.fromLong(peers[i].ip);
			}

			cb(null, {peers: peers});
		});
	});
};

shared.getPeer = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			ip_str: {
				type: "string",
				minLength: 1
			},
			port: {
				type: "integer",
				minimum: 0,
				maximum: 65535
			}
		},
		required: ['ip_str', 'port']
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		try {
			var ip_str = ip.toLong(query.ip_str);
		} catch (e) {
			return cb("Invalid peer");
		}

		privated.getByFilter({
			ip: ip_str,
			port: port
		}, function (err, peers) {
			if (err) {
				return cb("Peer not found");
			}

			var peer = peers.length ? peers[0] : null;

			if (peer) {
				peer.ip = ip.fromLong(peer.ip);
			}

			cb(null, {peer: peer || {}});
		});
	});
};

shared.version = function (req, cb) {
	cb(null, {version: library.config.version, build: library.build});
};

// Export
module.exports = Peer;
