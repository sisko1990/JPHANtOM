<?php
/**
 * @copyright Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @copyright Copyright (C) 2013 Jan Erik Zassenhaus. All rights reserved.
 * @license   GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;


/**
 * JPHANtOM library: Password validation
 *
 * @package    Joomla.Library
 * @subpackage JPhantom.Password.Validation
 */
class JPhantomPasswordValidation
{
    /**
     * The password that should be validated.
     *
     * @access private
     * @var string
     */
    private $password = null;

    /**
     * Create new objects with the password to check.
     *
     * @access public
     *
     * @param string $password The password that should be validated.
     *
     * @throws Exception
     */
    public function __construct($password)
    {
        if (!empty($password))
        {
            $this->password = $password;
        }
        else
        {
            throw new Exception('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');
        }
    }

    /**
     * Changes the password in the object after the object is already created.
     *
     * @access public
     * @see __construct()
     *
     * @param string $password The password that should be validated.
     */
    public function setPassword($password)
    {
        $this->__construct($password);
    }

    /**
     * Check if the password consists of digits.
     *
     * @access public
     * @return boolean
     */
    public function hasDigits()
    {
        if (preg_match('/[[:digit:]]/', $this->password))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    /**
     * Check if the password consists of upper case letters.
     *
     * @access public
     * @return boolean
     */
    public function hasUpperCaseLetters()
    {
        if (preg_match('/[[:upper:]]/', $this->password))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    /**
     * Check if the password consists of lower case letters.
     *
     * @access public
     * @return boolean
     */
    public function hasLowerCaseLetters()
    {
        if (preg_match('/[[:lower:]]/', $this->password))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    /**
     * Check if the password consists of upper and lower case letters.
     *
     * @access public
     * @return boolean
     */
    public function hasUpperAndLowerCaseLetters()
    {
        if ($this->hasUpperCaseLetters() && $this->hasLowerCaseLetters())
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    /**
     * Check if the password consists of forbidden text.
     *
     * @access public
     *
     * @param string|array $text The forbidden text as a single text or as an array for more than one value.
     *
     * @return boolean
     */
    public function hasForbiddenText($text)
    {
        if (is_string($text))
        {
            if (stripos($text, $this->password) !== false)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        elseif (is_array($text))
        {
            foreach ($text as $key => $value)
            {
                if (stripos($value, $this->password) !== false)
                {
                    return true;
                }
            }
            return false;
        }
    }
}