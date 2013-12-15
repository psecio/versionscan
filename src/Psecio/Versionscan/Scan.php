<?php

namespace Psecio\Versionscan;

class Scan
{
    private $checks = array();

    public function execute($phpVersion = null)
    {
        $phpVersion = ($phpVersion === null) ? PHP_VERSION : $phpVersion;

        // pull in the Scan checks
        $checks = json_decode(file_get_contents(__DIR__.'/checks.json'));

        foreach ($checks->checks as $index => $check) {
            $check = new \Psecio\Versionscan\Check($check);
            $result = $check->isVulnerable($phpVersion);
            $check->setResult($result);

            $this->checks[] = $check;
        }
    }

    public function getChecks()
    {
        return $this->checks;
    }
}