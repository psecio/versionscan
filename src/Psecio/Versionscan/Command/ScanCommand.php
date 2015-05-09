<?php
namespace Psecio\Versionscan\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputOption;
use Psecio\Versionscan\Exceptions\FormatNotFoundException;

class ScanCommand extends Command
{
    protected function configure()
    {
        $this->setName('scan')
            ->setDescription('Report back vulnerabilities for the current PHP version')
            ->setDefinition(array(
                new InputOption('php-version', 'php-version', InputOption::VALUE_OPTIONAL, 'PHP version to check'),
                new InputOption('fail-only', 'fail-only', InputOption::VALUE_NONE, 'Show only failures'),
                new InputOption('sort', 'sort', InputOption::VALUE_OPTIONAL, 'Sort Results By Column (cve, risk)'),
                new InputOption('format', 'format', InputOption::VALUE_OPTIONAL, 'Output format'),
                new InputOption('output', 'output', InputOption::VALUE_OPTIONAL, 'Directory for file output types'),
            ))
            ->setHelp(
                'Execute the scan on the current PHP version'
            );
    }

    /**
     * Execute the "scan" command
     *
     * @param  InputInterface $input Input object
     * @param  OutputInterface $output Output object
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $phpVersion = $input->getOption('php-version');
        $failOnly = $input->getOption('fail-only');
        $sort = $input->getOption('sort');
        $outputPath = $input->getOption('output');

        $format = $input->getOption('format');
        $format = $format === null ? 'console' : strtolower($format);

        if ($format === 'html' && $outputPath === null) {
            throw new \InvalidArgumentException('Output path must be set for format "HTML"');
        }

        $scan = new \Psecio\Versionscan\Scan();
        $scan->execute($phpVersion);

        $results = array();
        $failCount = 0;

        foreach ($scan->getChecks() as $check) {
            if ($failOnly !== null && $check->getResult() !== true) {
                continue;
            }

            $status = $check->getResult() === true ? 'fail' : 'pass';
            if ($status === 'fail') {
                $failCount++;
            }

            $results[] = array(
                'status'  => $status,
                'cve-id'  => $check->getCveId(),
                'risk'    => $check->getThreat(),
                'summary' => trim($check->getSummary()),
            );
        }

        if ($sort !== false) {
            usort($results, function($row1, $row2) use ($sort) {
                $sort = strtolower($sort);

                if ($sort == 'cve') {
                    $r1 = str_replace(array('CVE', '-'), '', $row1['cve-id']);
                    $r2 = str_replace(array('CVE', '-'), '', $row2['cve-id']);

                    return $r1 > $r2 ? -1 : 1;
                } elseif ($sort == 'risk') {
                    $r1 = (integer) $row1['risk'];
                    $r2 = (integer) $row2['risk'];

                    return $r1 > $r2 ? -1 : 1;
                }
            });
        }

        $options = array(
            'phpVersion'  => $scan->getVersion(),
            'checksCount' => count($scan->getChecks()),
            'failCount'   => $failCount,
            'outputPath'  => $outputPath,
        );

        $formatClass = '\\Psecio\\Versionscan\\Command\\ScanCommand\\Output\\' . ucwords($format);
        if (!class_exists($formatClass)) {
            throw new FormatNotFoundException(sprintf('Output format "%s" not found', $format));
        }

        $outputHandler = new $formatClass($output, $options);

        return $outputHandler->render($results, $this);
    }
}
