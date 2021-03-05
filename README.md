# 两步验证

```
<?php

/**
 * 验证类
 */
class authenticator
{
	public $digest = 'sha1';
	public $digits = 6;
	public $secret;
	public $interval = 30;

	/**
     * The interval in seconds for a one-time password timeframe
     * Defaults to 30
     * @var integer
     */
	function __construct($secret){
		$this->secret = $secret;
	}

	/**
     *  Get the password for the current timestamp value 
     *
     *  @return integer the current One Time Password
     */
	public function now() {
	   return $this->generateOTP($this->timecode(time()));
	}

	/**
     * Verify if a password is valid for a specific counter value
     *
     * @param integer $otp the one-time password 
     * @param integer $timestamp the timestamp for the a given time, defaults to current time.
     * @return  bool true if the counter is valid, false otherwise
     */
    public function verify($otp, $timestamp = null) {
		if($timestamp === null) {
			$timestamp = time();
		}
		return ($otp == $this->generateOTP($this->timecode($timestamp)));
    }

	/**
     * Transform a timestamp in a counter based on specified internal
     *
     * @param integer $timestamp
     * @return integer the timecode
     */
	protected function timecode($timestamp) {
		return intval(intval($timestamp) * 1000 / ($this->interval * 1000));
	}

	/**
     *  Get the password for the current timestamp value 
     *
     *  @return integer the current One Time Password
     */
	protected function generateOTP($input) {
	  	$hash = hash_hmac($this->digest, $this->intToBytestring($input), $this->byteSecret());
		foreach(str_split($hash, 2) as $hex) { // stupid PHP has bin2hex but no hex2bin WTF
			$hmac[] = hexdec($hex);
		}
		$offset = $hmac[19] & 0xf;
		$code = ($hmac[$offset+0] & 0x7F) << 24 |
			($hmac[$offset + 1] & 0xFF) << 16 |
			($hmac[$offset + 2] & 0xFF) << 8 |
			($hmac[$offset + 3] & 0xFF);
		return str_pad($code % pow(10, $this->digits),$this->digits,0,STR_PAD_LEFT);
	}

	protected function intToBytestring($int) {
		$result = [];
		while($int != 0) {
			$result[] = chr($int & 0xFF);
			$int >>= 8;
		}
		return str_pad(join(array_reverse($result)), 8, "\000", STR_PAD_LEFT);
	}

	protected function byteSecret() {
		return $this->base32_decode($this->secret);
    }

	protected function base32_decode($d)
	{
		list($t, $b, $r) = ["ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "", ""];
		foreach(str_split($d) as $c) {
	    	$b = $b . sprintf("%05b", strpos($t, $c));
		}
		foreach(str_split($b, 8) as $c) {
	    	$r = $r . chr(bindec($c));
		}
		return($r);
	}
}

$opt = new authenticator('key');
var_dump($opt->now());
var_dump($opt->verify('203172'));
```