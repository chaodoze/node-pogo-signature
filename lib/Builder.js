'use strict';

const protobuf = require('protobufjs');
const utils = require('./utils');
const crypto = require('crypto');
const longjs = require('long');
const path = require('path');

const sigFile = `
syntax = "proto3";

message Signature {

    message LocationFix {
        string provider = 1; // "network", "gps", "fused", possibly others
        uint64 timestamp_since_start = 2; // in ms
        float latitude = 13;
        float longitude = 14;

        // ??? shows up in struct, dunno where these go
        // float device_speed;
        // float device_course;
        float horizontal_accuracy = 20; // iOS only? (range seems to be -1 to +1)
        float altitude = 21;
        float vertical_accuracy = 22; // iOS only? (range seems to be ~10-12)
        uint64 provider_status = 26; // Usually 3 (possibly GPS status: 1 = no fix, 2 = acquiring/inaccurate, 3 = fix acquired)
                           // On iOS there are some LocationFixes with unk26=1 and everything else empty
        uint32 floor = 27; // No idea what this is, seems to be optional
        uint64 location_type = 28; // Always 1 (if there is data at all)
    }

    // don't really care about this since we're not using it
    message AndroidGpsInfo {
        uint64 time_to_fix = 1;
        repeated int32 satellites_prn = 2;
        repeated float snr = 3;
        repeated float azimuth = 4;
        repeated float elevation = 5;
        repeated bool has_almanac = 6;
        repeated bool has_ephemeris = 7;
        repeated bool used_in_fix = 8;
    }

    message SensorInfo {
        uint64 timestamp_snapshot = 1; // in ms
        double magnetometer_x = 3;
        double magnetometer_y = 4;
        double magnetometer_z = 5;
        double angle_normalized_x = 6;
        double angle_normalized_y = 7;
        double angle_normalized_z = 8;
        double accel_raw_x = 10;
        double accel_raw_y = 11;
        double accel_raw_z = 12;
        double gyroscope_raw_x = 13;
        double gyroscope_raw_y = 14;
        double gyroscope_raw_z = 15;
        double accel_normalized_x = 16;
        double accel_normalized_y = 17;
        double accel_normalized_z = 18;
        uint64 accelerometer_axes = 19; // Always 3
    }

    message DeviceInfo {
        string device_id = 1; // Hex string
        string android_board_name = 2;
        string android_bootloader = 3;
        string device_brand = 4; // On Android: product.brand
        string device_model = 5; // On Android: product.device
        string device_model_identifier = 6; // Android only, build.display.id
        string device_model_boot = 7;  // On Android: boot.hardware
        string hardware_manufacturer = 8; // On Android: product.manufacturer
        string hardware_model = 9;  // On Android: product.model
        string firmware_brand = 10; // On Android: product.name, on iOS: "iPhone OS"
        string firmware_tags = 12; // Android only, build.tags
        string firmware_type = 13; // On Android: build.type, on iOS instead: iOS version
        string firmware_fingerprint = 14; // Android only, build.fingerprint
    }

    message ActivityStatus {
        // all of these had 1 as their value
        uint64 start_time_ms = 1;
        bool unknown_status = 2;
        bool walking = 3;
        bool running = 4;
        bool stationary = 5;
        bool automotive = 6;
        bool tilting = 7;
        bool cycling = 8;
        bytes status = 9;
    }

    uint64 timestamp_since_start = 2; // in ms
    repeated LocationFix location_fix = 4;
    AndroidGpsInfo gps_info = 5;
    SensorInfo sensor_info = 7;
    DeviceInfo device_info = 8;
    ActivityStatus activity_status = 9;
    uint32 location_hash1 = 10; // Location1 hashed based on the auth_token - xxHash32
    uint32 location_hash2 = 20; // Location2 hashed based on the auth_token - xxHash32
    bytes session_hash = 22; // unique per session. Generation unknown but pointed to by 0001B8614
    uint64 timestamp = 23; // epoch timestamp in ms
    repeated uint64 request_hash = 24; // hashes of each request message in a hashArray - xxhash64
    int64 unknown25 = 25; // for 0.33 its static -8537042734809897855 or 0x898654dd2753a481 - xxhash64

    // Addresses for the corresponding hash functions:
    //    xxHash32              00054D28
    //    xxhash64              000546C8 - Feeds into 00053D40

}
`
const u6File = `
syntax = "proto3";

message Unknown6 {
	int32 request_type = 1; // 5 for IAPs, 6 is unknown still
	Unknown2 unknown2 = 2;

	message Unknown2 {
		bytes encrypted_signature = 1;
	}
}
`
const PROTO_Signature = protobuf.loadProto(sigFile).build().Signature;
const PROTO_u6 = protobuf.loadProto(u6File).build().Unknown6;

/**
 * the signature builder
 * @constructor
 * @param {Object} [options] - a set of options and defaults to send to the signature builder
 * @param {number} [options[].initTime] - time in ms to use as the app's startup time
 * @param {Buffer} [options[].unk22] - a 32-byte Buffer to use as `unk22`
 */
let Builder = function(options) {
    if (!options) options = {}
    this.initTime = options.initTime || new Date().getTime();
    this.options = {
        session_hash: options.session_hash || options.unk22 || crypto.randomBytes(32)
    };
};

/**
 * sets the location to be used in signature building
 * @param {number} lat - latitude
 * @param {number} lng - longitude
 * @param {number} [alt=0] - altitude
 */
Builder.prototype.setLocation = function(lat, lng, alt) {
    if (!alt) alt = 0;
    this.lat = lat;
    this.lng = lng;
    this.alt = alt;
}

/**
 * sets the auth_ticket to be used in signature building
 * @param {Buffer|Object} authTicket - protobufjs constructor OR raw buffer containing bytes (must pass true for `isEncoded` when passing a Buffer)
 * @param {boolean} [isEncoded=false] - set to true if the authTicket is a protobuf encoded Buffer
 */
Builder.prototype.setAuthTicket = function(authTicket, isEncoded) {
    if (isEncoded) {
        this.authTicket = authTicket;
    } else {
        if (authTicket.encode) {
            this.authTicket = authTicket.encode().toBuffer();
        }
    }
}

/**
 * builds an unencrypted signature returned as a protobuf object or Buffer
 * @param {Object|Object[]|Buffer|Buffer[]} requests - array of RPC requests (protobuf objects or encoded protobuf Buffers) to be used in the signature generation
 * @param {boolean} [retRawBytes=false] - if true, will return a protobuf encoded Buffer of the resulting signature rather than a protobuf object
 * @returns {Object|Buffer}
 */
Builder.prototype.buildSignature = function(requests, retRawBytes) {
    if (!Array.isArray(requests)) {
        requests = [requests];
    }

    let options = {
        location_hash1: utils.hashLocation1(this.authTicket, this.lat, this.lng, this.alt).toNumber(),
        location_hash2: utils.hashLocation2(this.lat, this.lng, this.alt).toNumber(),
        timestamp: new Date().getTime(),
        timestamp_since_start: (new Date().getTime() - this.initTime)
    };
    for(let option in this.options) {
        options[option] = this.options[option];
    }
    let signature = new PROTO_Signature(options);

    requests.forEach(request => {
        const requestBytes = (request.encode) ? request.encode().toBuffer() : request;
        const reqHash = utils.hashRequest(this.authTicket, requestBytes).toString();
        signature.request_hash.push(longjs.fromString(reqHash, true, 10));
    });

    if (retRawBytes) return signature.encode().toBuffer();
    return signature;
}

/**
 * builds a signature given requests, and encrypts it afterwards
 * @global
 * @param {Object|Object[]|Buffer|Buffer[]} requests - array of RPC requests (protobuf objects or encoded protobuf Buffers) to be used in the signature generation
 * @param {encryptCallback} cb - function to be called when encryption is completed
 */
Builder.prototype.encrypt = function(requests, cb) {
    const signature = this.buildSignature(requests, true);
    utils.encrypt(signature, crypto.randomBytes(32), cb);
}

/**
 * builds a signature given requests, and encrypts it afterwards
 * @global
 * @param {Object|Object[]|Buffer|Buffer[]} requests - array of RPC requests (protobuf objects or encoded protobuf Buffers) to be used in the signature generation
 * @returns {Buffer} encrypted bytes returned from encryption
 */
Builder.prototype.encryptSync = function(requests) {
    const signature = this.buildSignature(requests, true);
    return utils.encryptSync(signature, crypto.randomBytes(32));
}

/**
 * returns a completely-populated unknown6 protobuf object to be used in a Request Envelope
 * @param {Object|Object[]|Buffer|Buffer[]} requests - array of RPC requests (protobuf objects or encoded protobuf Buffers) to be used in the signature generation
 * @param {Function} callback - Callback executed when encryption and unknown6 constructing is complete.
 */
Builder.prototype.getUnknown6 = function(requests, cb) {
    this.encrypt(requests, (err, result) => {
        if (err) return cb(err);
        cb(null, new PROTO_u6({
            request_type: 6,
            unknown2: new PROTO_u6.Unknown2({
                encrypted_signature: result
            })
        }));
    });
}

module.exports = Builder;
