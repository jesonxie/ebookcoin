var constants = require('./constants.js');
/**
 * Get time from Ebookcoin epoch.
 * @param {number|undefined} time Time in unix seconds
 * @returns {number}
 */
//建立创世时间
function beginEpochTime() {
    var d = new Date(Date.UTC(2016, 5, 20, 0, 0, 0, 0)); //Testnet starts from 2016.6.20

    return d;
}
//获得当前距离创世时间多少秒
function getEpochTime(time) {
    if (time === undefined) {
        time = (new Date()).getTime();
    }
    var d = beginEpochTime();
    var t = d.getTime();
    return Math.floor((time - t) / 1000);
}
//constants.slots.interval=10
module.exports = {
    //获得当前距离创世时间多少秒
    getTime: function(time) {
        return getEpochTime(time);
    },
//获得当前的真实时间
    getRealTime: function(epochTime) {
        if (epochTime === undefined) {
            epochTime = this.getTime()
        }
        var d = beginEpochTime();
        var t = Math.floor(d.getTime() / 1000) * 1000;
        return t + epochTime * 1000;
    },
//根据当前时间(距离创世时间多少秒)计算slot
    getSlotNumber: function(epochTime) {
        if (epochTime === undefined) {
            epochTime = this.getTime()
        }
        return Math.floor(epochTime / constants.slots.interval);
    },
//根据slot来计算时间(距离创世时间多少秒)
    getSlotTime: function(slot) {
        return slot * constants.slots.interval;
    },

    getNextSlot: function() {
        var slot = this.getSlotNumber();

        return slot + 1;
    },

    getLastSlot: function(nextSlot) {
        return nextSlot + constants.delegates;
    }
}
