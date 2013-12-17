<?php

namespace Psecio\Versionscan;

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
     * @return array Set of fix versions
     */
    public function getVersions()
    {
        return $this->fixVersions;
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
     * Check to see if the current installation is vulneravle to the issue
     * 
     * @param string $phpVersion PHP version string
     * @return boolean Pass/fail status
     */
    public function isVulnerable($phpVersion)
    {
        $versions = $this->getVersions();

        // look at the versions and find the major version
        preg_match('/([0-9]+)\.([0-9]+)\.([0-9]+)/', $phpVersion, $matches);
        if (count($matches) >= 2) {
            $majorVersion = $matches[1].'.'.$matches[2];

            // now match it against our $versions
            foreach($versions as $version) {
                if (strpos($version, $matches[1].'.'.$matches[2]) !== false) {
                    if (version_compare($phpVersion, $version) === -1) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}