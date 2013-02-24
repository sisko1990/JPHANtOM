<?php

/**
 * @copyright   Copyright (C) 2013 Jan Erik Zassenhaus. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

// Import some helpers
jimport('joomla.user.helper');

abstract class JPhantomLib
{
    /**
     * Holds all possible Joomla! password hashes.
     *
     * @static
     * @access private
     * @var array
     */
    private static $available_jhashes = array('ssha', 'sha', 'crypt', 'smd5', 'md5-hex', 'aprmd5', 'md5-base64');

    /**
     * This method checks if we have a valid Joomla! user password and returns the hash algorithm.
     * If it is not a Joomla! hash it will return false.
     *
     * @static
     * @access public
     * @return string|false
     */
    public static function getJoomlaPasswordHashAlgorithmForPassword($password_hash, $password_hash_algorithm, $password)
    {
        // If password has ":" in it, it is a Joomla! password hash
        if ((substr($password_hash, 0, 3) !== '$S$') && (strpos($password_hash, ':') !== false))
        {
            $parts = explode(':', $password_hash);
            $crypt = $parts[0];
            $salt = @$parts[1];
            $testcrypt = JUserHelper::getCryptedPassword($password, $salt, $password_hash_algorithm);

            if ($crypt === $testcrypt)
            {
                return $password_hash_algorithm;
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
            // Hash format is not a Joomla! one.
            return false;
        }
    }



}