<?php

namespace Psecio\Versionscan;

use \InvalidArgumentException;

class Check
{
    /**
     * CVE ID for the check
     * @var string
     */
    private $cveid = null;

    /**
     * Summary (description) of the issue
     * @var string
     */
    private $summary = '';

    /**
     * The threat of the vulnerability (out of 10)
     * @var int
     */
    private $threat = 0;

    /**
     * Set of versions when the issue was fixed
     * @var array
     */
    private $fixVersions = array();

    /**
     * Pass/fail result
     * @var boolean
     */
    private $result = false;

    /**
     * Init the check object with optional check data
     *
     * @param type $checkData Set of data to assign to the check
     */
    public function __construct($checkData = null)
    {
        if ($checkData !== null) {
            $this->setData($checkData);
        }
    }

    /**
     * Assign the check data to the current object
     *
     * @param array $checkData Check data
     */
    public function setData($checkData)
    {
        $checkData = (is_object($checkData))
            ? get_object_vars($checkData) : $checkData;

        foreach ($checkData as $key => $data) {
            $this->$key = $data;
        }
    }

    /**
     * Set the pass/fail result
     *
     * @param boolean $result Pass/fail result
     */
    public function setResult($result)
    {
        $this->result = $result;
    }

    /**
     * Get the current pass/fail result
     *
     * @return boolean Pass/fail result
     */
    public function getResult()
    {
        return $this->result;
    }

    /**
     * Mark the test as passed
     */
    public function pass()
    {
        $this->setResult(true);
    }

    /**
     * Mark the test as failed
     */
    public function fail()
    {
        $this->setResult(false);
    }

    /**
     * Get the fix versions of the check
     *
     * @param string $type Type
     * @return array Set of fix versions
     */
    public function getVersions($type = 'base')
    {
        return $this->fixVersions->$type;
    }

    /**
     * Get the threat for the check
     *
     * @return integer threat
     */
    public function getThreat()
    {
        return $this->threat;
    }

    /**
     * Get the CVE ID for the check
     *
     * @return string CVE ID
     */
    public function getCveId()
    {
        return $this->cveid;
    }

    /**
     * Get the summary description of the check
     *
     * @return string Description
     */
    public function getSummary()
    {
        return $this->summary;
    }

    /**
     * Sort the versions from lowest to highest
     *
     * @param  array $versions Set of PHP version numbers
     * @return arrya Sorted version numbers list
     */
    public function sortVersions($versions)
    {
        usort($versions, function($version1, $version2) {
            return version_compare($version1, $version2);
        });
        return $versions;
    }

    /**
     * Check to see if the current installation is vulneravle to the issue
     *
     * @param string $phpVersion PHP version string
     * @return boolean Pass/fail status
     */
    public function isVulnerable($phpVersion)
    {
        // get the major version of the one we're using
        if (!preg_match('/([0-9]+\.[0-9]+)\.?([0-9]+)?/', $phpVersion, $matches)) {
            throw new InvalidArgumentException('Could not determine major version');
        }
        $majorVersion = $matches[1];

        // check through the versions and see if any of them contain the major version
        $versions = $this->sortVersions($this->getVersions());
        $found = array_values(
            array_filter($versions, function($version) use ($majorVersion) {
                return (strpos($version, $majorVersion) !== false) ? true : false;
            })
        );

        if (count($found) > 0) {
            // we found one that matches our version
            $foundVersion = $found[0];
            $check = version_compare($foundVersion, $phpVersion);
            return ( $check === -1 || $check === 0) ? false : true;
        }
        
        // No matches found, then we can assume that this version is safe. Minor versions
        // might have bug fixes for bugs found in a higher major versions or might not
        // have the vulnerability at all.
        return false;
    }

    /**
     * Return the check information as an array
     *
     * @return array Check details
     */
    public function toArray()
    {
        return array(
            'threat' => $this->getThreat(),
            'cveid' => $this->getCveId(),
            'summary' => $this->getSummary(),
            'fixVersions' => $this->getVersions()
        );
    }
}