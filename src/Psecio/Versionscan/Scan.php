<?php

namespace Psecio\Versionscan;

class Scan
{
    /**
     * Set of checks to run
     * @var array
     */
    private $checks = array();

    /**
     * Execute the scan
     * 
     * @param type $phpVersion Optional PHP version
     */
    public function execute($phpVersion = null)
    {
        $phpVersion = ($phpVersion === null) ? PHP_VERSION : $phpVersion;

        // pull in the Scan checks
        $checks = $this->loadChecks();
        $results = array();
        foreach ($checks->checks as $index => $check) {
            $check = new \Psecio\Versionscan\Check($check);
            $result = $check->isVulnerable($phpVersion);
            $check->setResult($result);

            $results[] = $check;
        }
        $this->setChecks($results);
    }

    /**
     * Load the checks from the JSON file
     * 
     * @return object Configuration loaded as an object
     */
    public function loadChecks()
    {
        // pull in the Scan checks
        $path = __DIR__.'/checks.json';
        if (is_file($path)) {
            $checks = @json_decode(file_get_contents($path));
            if ($checks === false) {
                throw new Exception('Invalid check configuration');
            }
            return $checks;
        } else {
            throw new Exception('Could not load check file '.$path);
        }
    }

    /**
     * Set the results of the check evaluation
     * 
     * @param array $checks Set of check evaluation results
     */
    public function setChecks(array $checks)
    {
        $this->checks = $checks;
    }

    /**
     * Get the current check result set
     * 
     * @return array Check results
     */
    public function getChecks()
    {
        return $this->checks;
    }
}