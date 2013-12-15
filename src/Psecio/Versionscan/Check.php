<?php

namespace Psecio\Versionscan;

class Check
{
    private $cveid = null;
    private $summary = '';
    private $fixVersions = array();
    private $result = false;

    public function __construct($checkData)
    {
        $this->setData($checkData);
    }

    public function setData($checkData)
    {
        $checkData = (is_object($checkData))
            ? get_object_vars($checkData) : $checkData;

        foreach ($checkData as $key => $data) {
            $this->$key = $data;
        }
    }

    public function setResult($result)
    {
        $this->result = $result;
    }

    public function getResult()
    {
        return $this->result;
    }

    public function pass()
    {
        $this->setResult(true);
    }

    public function fail()
    {
        $this->setResult(false);
    }

    public function getVersions()
    {
        return $this->fixVersions;
    }

    public function getCveId()
    {
        return $this->cveid;
    }

    public function getSummary()
    {
        return $this->summary;
    }

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