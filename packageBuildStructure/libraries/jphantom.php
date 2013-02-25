<?php

/**
 * @copyright   Copyright (C) 2013 Jan Erik Zassenhaus. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

// Import some helpers
jimport('joomla.user.helper');

class JPhantomLib
{

    /**
     * Saves the default global password hash algorithm
     *
     * @access private
     * @var string
     */
    private $default_hash_algorithm = 'md5-hex';

    /**
     * Holds all possible Joomla! password hashes.
     *
     * @static
     * @access private
     * @var array
     */
    private static $available_jhashes = array('ssha', 'sha', 'crypt', 'smd5', 'md5-hex', 'aprmd5', 'md5-base64');


    /**
     * Sets the default hash algorithm.
     * Possible values: ssha, sha, crypt, smd5, md5-hex, aprmd5, md5-base64 or drupal
     *
     * @access public
     * @param string $hash_algorithm The hash algorithm to use as default
     */
    public function setDefaultHashAlgorithm($hash_algorithm)
    {
        if (in_array($hash_algorithm, self::$available_jhashes) || $hash_algorithm === 'drupal')
        {
            $this->default_hash_algorithm = $hash_algorithm;
        }
    }

    /**
     * This method checks if we have a valid Joomla! user password and returns the hash algorithm.
     * If it is not a Joomla! hash or the password hash comparison is wrong it will return false.
     *
     * @access public
     * @param string $password_hash_and_salt The password hash from database
     * @param string $password               The password in plain text
     * @return string|false
     */
    public function getJoomlaPasswordHashAlgorithmForPassword($password_hash_and_salt, $password)
    {
        // If password has ":" in it, it is a Joomla! password hash
        if ((substr($password_hash_and_salt, 0, 3) !== '$S$') && (strpos($password_hash_and_salt, ':') !== false))
        {
            $parts = explode(':', $password_hash_and_salt);
            $crypt = $parts[0];
            $salt = @$parts[1];
            $testcrypt = JUserHelper::getCryptedPassword($password, $salt, $this->default_hash_algorithm);

            if ($crypt === $testcrypt)
            {
                return $this->default_hash_algorithm;
            }
            else
            {
                foreach (self::$available_jhashes as $hashtype)
                {
                    $testcrypt = JUserHelper::getCryptedPassword($password, $salt, $hashtype);
                    if ($crypt === $testcrypt)
                    {
                        return $hashtype;
                    }
                }
                // No match with the available Joomla! hashes
                return false;
            }
        }
        else
        {
            // No Joomla! password hash format
            return false;
        }
    }



    /**
     * This method checks if we have a valid Drupal user password and returns true.
     * If it is not a Drupal hash or the password hash comparison is wrong it will return false.
     *
     * @access public
     * @param string $password_hash_and_salt The password hash from database
     * @param string $password               The password in plain text
     * @return string|false
     */
    public function checkDrupalPasswordHashAlgorithmForPassword($password_hash_and_salt, $password)
    {
        // Check if we have a Drupal hash
        if (substr($password_hash_and_salt, 0, 3) === '$S$')
        {
            jimport('jphantom.hashes.drupal_password_hash');

            if (user_check_password($password, $password_hash_and_salt) === true)
            {
                // Password is correct
                return true;
            }
            else
            {
                // Password is wrong
                return false;
            }
        }
        else
        {
            // No Drupal password hash format
            return false;
        }
    }


    /**
     * Check if the password is valid. If it is rigth it returns true otherwise false.
     * This function also updates the hash if it is not the default hash.
     *
     * @access public
     * @param string $password_hash_and_salt The password hash from database
     * @param string $password               The password in plain text
     * @return boolean
     */
    public function checkPasswordWithStoredHash($password_hash_and_salt, $password)
    {
        // @TODO: Implement!
    }



}