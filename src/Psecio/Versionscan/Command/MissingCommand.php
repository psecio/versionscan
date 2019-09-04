<?php
namespace Psecio\Versionscan\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputOption;
use KubAT\PhpSimple\HtmlDomParser;

class MissingCommand extends Command
{
    private $verbose = false;
    private $checksFilePath;
    private $checksFileContents;
    private $checksList;

    protected function configure()
    {
        $this->setName('missing')
            ->setDescription('Find vulnerabilities missing from current checks')
            ->setDefinition(array(
                new InputOption('save-results', 'save-results', InputOption::VALUE_OPTIONAL, 'Save missing vulnerabilities to the checks list'),
            ))
            ->setHelp(
                'Find vulnerabilities missing from current checks'
            );
    }

    /**
     * Execute the "missing" command
     *
     * @param  InputInterface $input Input object
     * @param  OutputInterface $output Output object
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $this->verbose = $input->getOption('verbose');
        $this->checksFilePath = __DIR__ . '/../../../Psecio/Versionscan/checks.json';
        $saveResults = $input->getOption('save-results');

        // Get our current checks
        $this->checksFileContents = json_decode(file_get_contents($this->checksFilePath), true);
        $this->checksList = [];
        foreach ($this->checksFileContents['checks'] as $check) {
            if (!in_array($check['cveid'], $this->checksList)) {
                $this->checksList[] = $check['cveid'];
            }
        }

        $v5Results = $this->parseChangeLog(file_get_contents('http://php.net/ChangeLog-5.php'), $output);
        $v7Results = $this->parseChangeLog(file_get_contents('http://php.net/ChangeLog-7.php'), $output);

        $fixVersions = array_merge($v5Results, $v7Results);

        if (empty($fixVersions)) {
            $output->writeLn('No missing versions/CVEs detected');
        } else {
            $jsonOutput = json_encode(array_values($fixVersions), JSON_PRETTY_PRINT);
            echo $jsonOutput."\n\n";
        }

        if ($this->verbose === true) {
            $output->writeLn('Missing records found: '.count($fixVersions));
        }

        if ($saveResults !== false) {
            $this->saveResults($fixVersions);
        }
    }

    private function parseChangeLog($changelog, $output)
    {
        // Parse the changelog into versions
        preg_match_all('#<section class="version" id="([0-9\.]+)">(.+?)</section>#ms', $changelog, $matches);

        $cveIdList = [];
        $fixVersions = [];

        // print_r($matches);
        foreach ($matches[0] as $index => $match) {
            $versionId = $matches[1][$index];

            // see if we have any CVEs
            if (strstr($match, 'CVE') === false) {
                continue;
            }

            // Extract our CVEs
            preg_match_all('/CVE-[0-9]+-[0-9]+/', $match, $cveList);

            // @TODO limit it down to just five for throttling's sake
            $cveList[0] = array_slice($cveList[0], 0, 1);

            // print_r($cveList);
            foreach ($cveList[0] as $cveId) {
                if (in_array($cveId, $this->checksList) === true) {
                    continue;
                }

                $cveIdList[] = $cveId;
                $cveDetail = $this->getCveDetail($cveId, $output);
                if ($cveDetail === false) {
                    continue;
                }

                $dom = HtmlDomParser::str_get_html($cveDetail);

                $cveScore = $dom->find('div.cvssbox')[0]->plaintext;
                $cveSummary = explode("\n", trim($dom->find('div.cvedetailssummary')[0]->plaintext))[0];

                $output->writeLn('('.$cveScore.') fixed in '.$versionId);

                if (!isset($fixVersions[$cveId])) {
                    $fixVersions[$cveId] = [
                        'threat' => $cveScore,
                        'cveid' => $cveId,
                        'summary' => trim($cveSummary),
                        'fixVersions' => ['base' => []]
                    ];
                }
                $fixVersions[$cveId]['fixVersions']['base'][] = $versionId;
            }
        }

        return $fixVersions;
    }

    private function getCveDetail($cveId, $output)
    {
        // save the contents locally
        $cacheFile = '/tmp/cache-'.$cveId.'.txt';

        if (!is_file($cacheFile)) {
            // Get the info for the CVE
            $message = 'Fetching for '.$cveId;

            $cveUrl = 'http://www.cvedetails.com/cve-details.php?t=1&cve_id='.$cveId;
            $cveDetail = file_get_contents($cveUrl);
            file_put_contents($cacheFile, $cveDetail);
        } else {
            $message = 'Cache found for '.$cveId;

            $cveDetail = file_get_contents($cacheFile);
        }

        if (strstr($cveDetail, 'Unknown CVE ID') !== false) {
            $message .= ' (no data)';
            $cveDetail = false;
        }

        if ($this->verbose === true) {
            $output->writeLn($message);
        }

        return $cveDetail;
    }

    private function saveResults($newChecks)
    {
        $allChecks = array_merge($this->checksFileContents['checks'], $newChecks);

        usort($allChecks, function($row1, $row2) {
            $row1Parts = explode('-', $row1['cveid']);
            $row2Parts = explode('-', $row2['cveid']);
            if ($row1Parts[1] != $row2Parts[1]) {
                return strnatcmp($row1Parts[1], $row2Parts[1]);
            }
            return strnatcmp($row1Parts[2], $row2Parts[2]);
        });

        foreach ($allChecks as $index => $check) {
            $versions = $allChecks[$index]['fixVersions']['base'];
            sort($versions);
            $allChecks[$index]['fixVersions']['base'] = $versions;
        }

        $output = [
            'checks' => $allChecks,
            'updatedAt' => Date('c')
        ];

        $json_data = json_encode($output, JSON_PRETTY_PRINT);
        file_put_contents($this->checksFilePath, $json_data);
    }
}
