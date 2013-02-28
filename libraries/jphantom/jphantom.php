<?php

/**
 * @copyright   Copyright (C) 2013 Jan Erik Zassenhaus. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;

// Import some helpers
jimport('joomla.user.helper');

// Define Exceptions
class InvalidPassException extends Exception {}
class NoUserException extends Exception {}

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
     * Saves a new password hash in database.
     *
     * @access private
     * @param string $hash    The password hash to save in database
     * @param int    $user_id The user_id from #_users
     * @throws Exception
     */
    private function updatePasswordHashInDatabase($hash, $user_id)
    {
        if (!empty($hash) && !empty($user_id) && is_int($user_id))
        {
            // Get a database object
            $db = JFactory::getDbo();

            $db->setQuery(
                'UPDATE #__users' .
                ' SET password = "' . $hash . '"' .
                ' WHERE id = ' . $user_id
            )->query();
        }
        else
        {
            throw new Exception('Hash and user_id cannot be empty or user_id is not an integer value!');
        }
    }


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
     * Generates a new hash for a password. The default hash algorithm is used for hashing.
     * A password should have at least 6 characters without whitespaces at the beginning and end.
     *
     * @access public
     * @param string $password_to_hash
     * @return string
     * @throws Exception
     */
    public function getHashForPassword($password_to_hash)
    {
        if (!empty($password_to_hash))
        {
            // Trim whitespaces
            $password_to_hash = trim($password_to_hash);

            if(strlen($password_to_hash) >= 6)
            {
                // Hash generation for Joomla! hashes
                if ($this->default_hash_algorithm !== 'drupal')
                {
                    $salt = JUserHelper::genRandomPassword(32);
                    $crypt = JUserHelper::getCryptedPassword($password_to_hash, $salt, $this->default_hash_algorithm);
                    $newHash = $crypt . ':' . $salt;
                }
                else
                {
                    jimport('jphantom.hashes.drupal_password_hash');

                    $newHash = user_hash_password($password_to_hash);
                }
                return $newHash;
            }
            else
            {
                throw new Exception('The password must contain at least 6 characters without whitespaces at beginning and end!');
            }
        }
        else
        {
            throw new Exception('A password cannot be empty for hashing!');
        }
    }


    /**
     * Check if the password is valid. If it is rigth it returns true otherwise false.
     * This function also updates the hash if it is not the default hash (only possible with correct $user_id parameter).
     *
     * @access public
     * @param string $password_hash_and_salt The password hash from database
     * @param string $password_to_check      The password in plain text
     * @param int    $user_id                The id from #_users to update a wrong hash
     * @return boolean
     * @throws InvalidPassException
     * @throws NoUserException
     */
    public function checkPasswordWithStoredHash($password_hash_and_salt, $password_to_check, $user_id = null)
    {
        if (!empty($password_hash_and_salt) && !empty($password_to_check))
        {
            switch ($this->default_hash_algorithm)
            {
                // The current algorithm for all users is a Joomla! one
                case in_array($this->default_hash_algorithm, self::$available_jhashes):
                    if ($this->getJoomlaPasswordHashAlgorithmForPassword($password_hash_and_salt,
                                                                         $password_to_check) !== false)
                    {
                        return true;
                    }
                    elseif ($this->checkDrupalPasswordHashAlgorithmForPassword($password_hash_and_salt,
                                                                               $password_to_check) === true)
                    {
                        if(!is_null($user_id) && is_int($user_id))
                        {
                            // Update to Joomla! hash
                            $newHash = $this->getHashForPassword($password_to_check);
                            $this->updatePasswordHashInDatabase($newHash, $user_id);
                        }
                        return true;
                    }
                    else
                    {
                        throw new InvalidPassException(JText::_('JGLOBAL_AUTH_INVALID_PASS'));
                    }
                    break;

                // The current algorithm for all users is a Drupal one
                case 'drupal':
                    if ($this->checkDrupalPasswordHashAlgorithmForPassword($password_hash_and_salt,
                                                                           $password_to_check) === true)
                    {
                        return true;
                    }
                    elseif ($this->getJoomlaPasswordHashAlgorithmForPassword($password_hash_and_salt,
                                                                             $password_to_check) !== false)
                    {
                        if(!is_null($user_id) && is_int($user_id))
                        {
                            // Update to Drupal hash
                            $newHash = $this->getHashForPassword($password_to_check);
                            $this->updatePasswordHashInDatabase($newHash, $user_id);
                        }
                        return true;
                    }
                    else
                    {
                        throw new InvalidPassException(JText::_('JGLOBAL_AUTH_INVALID_PASS'));
                    }
                    break;

                default:
                    throw new NoUserException(JText::_('JGLOBAL_AUTH_NO_USER'));
                    break;
            }
        }
    }



}