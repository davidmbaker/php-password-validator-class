<?php
/*
  * Project: simple_password_validator_class
  * File name: simple_password_class.php
  * Description: class to make secure password creation easy.
  * URL: http://www.trolldog.com/scripts/php/classes/simple+password_valitor
  *
  * Author: Mirko Kaiser, http://www.DavidBaker.us.com
  * Copyright (C) 2012 David M Baker
  * First created in USA on 1 December 2012
  * License: New BSD License
  *
	Copyright (c) 2012, David M Baker, http://www.davidbaker.us.com
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
		* Redistributions of source code must retain the above copyright
		  notice, this list of conditions and the following disclaimer.
		* Redistributions in binary form must reproduce the above copyright
		  notice, this list of conditions and the following disclaimer in the
		  documentation and/or other materials provided with the distribution.
		* Neither the name of the <organization> nor the
		  names of its contributors may be used to endorse or promote products
		  derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
*	
*
*/	
final class passwordValidator{
	
	//default settings
	
	protected $_mincharlen = 8;
	protected $_maxcharlen = 32;
	protected $_minnumeric = 1;
	protected $_minsymbols = 1;
	protected $_symbollist = "!@#$%&*";
	protected $_str = '';
	protected $_errorcode = '0';
	protected $_illegalchars = '';
	protected $_minletters = 3;
	protected $_minuppercase = 1;
	
	/**
	* function counts all numeric characters and returns count
	* @param string _$_str string to check
	* @return count ( int ) or boolean false is none found
	*/
	private function _countdigits() { 
		// used internally to count how many numeric chars there are
		preg_match_all( "/[0-9]/", $this->_str  , $_matches );
		return count ($_matches[0]);
	}
	
	private function _countUppers() {
		preg_match_all( "/[A-Z]/", $this->_str  , $_matches );
		return count ($_matches[0]);
	}
	
	public function getErrorCode() {
		return $this->_errorcode;
	}
	public function setIllegalChars($_string) {
		$this->_illegalchars = $_string;
	} 
	
	public function setMaxLength($_int) {
		$this->_maxcharlen = $_int;
	}
	
	public function setMinLetters($_int) {
		$this->_minletters = $_int;
	}
	
	public function setMinSymbols($_int){
		$this->_minsymbols = $_int;
	}
	
	public function setSymbolList($_string){
		$this->_symbollist = $_string;	
	}
	
	public function setMinNumeric($_string){
		$this->_minnumeric = $_string;	
	}
	
	public function setMinLength($_int){
		$this->_mincharlen = $_int;
	}
	
	public function setMinUpperCase($_int){
		$this->_minuppercase = $_int;
	}
	
	public function checkPWord( $_str ){
		if(trim( $this->_illegalchars ) == ''){
			$this->_illegalchars = false;
		}
		
		$this->_str = trim( $_str );
		
		if( $this->_str  == ''){ // check for empty string
			$this->_errorcode = "Empty String";
			return false;		// return false if empty
		}
		
		preg_match_all( '/\p{L}/', $this->_str , $matches);	
		
		if( count( $matches[0] ) < $this->_minletters ){
			$this->_errorcode = "Must contain at least ".$this->_minletters." letters.";
			return false;
		}
		
		// check for space
		if ( preg_match('/\s/', $this->_str ) ){
			$this->_errorcode = "Password can not contain spaces.";
			return false;		
		}
		
		// check minimum and maximum length
		
		$plen = strlen( $this->_str  );
		if( $plen < $this->_mincharlen || $plen > $this->_maxcharlen){
			$this->_errorcode = "Password must have at least ".$this->_mincharlen." but not more than ".$this->_maxcharlen." characters.";
			return false;
		}
		
		// check for numeric
		
		$_digitcount = $this->_countdigits();
		if($this->_minnumeric && $_digitcount < $this->_minnumeric){
			$this->_errorcode = "Password must have at least ".$this->_minnumeric." numbers.";
			return false;
		}
		
		// check for for uppers
		$_uppercasecount = $this->_countUppers();
		if($this->_minuppercase && $_uppercasecount < $this->_minuppercase){
			$this->_errorcode = "Password must have at least ".$this->_minuppercase." Upper Case Letters.";
			return false;	
		}
		
		// check for illegal chars
		if($this->_illegalchars){
			$_ill = str_split( $this->_illegalchars );
			$_illcount = 0;
			for( $t = 0; $t < strlen( $this->_str  ); $t++ ){
				if( in_array( $this->_str [$t], $_ill ) ){
					$_illcount++;
				}
			}
			
			if( $_illcount > 0 ){
				$this->_errorcode = "Password must not illegal characters (".$this->_illegalchars.").";
				return false;	
			}
		}
		
		// check for symbols
		if($this->_minsymbols){
			$_syms = str_split( $this->_symbollist );
			$_symcount = 0;
			for( $t = 0; $t < strlen( $this->_str  ); $t++ ){
				if( in_array( $this->_str [$t], $_syms ) ){
					$_symcount++;
				}
			}
			
			if( $_symcount < $this->_minsymbols ){
				$this->_errorcode = "Password must have at least ".$this->_minsymbols." symbols (".$this->_symbollist.").";
				return false;	
			}
		}
		
		return true;
	}
	
	
}	