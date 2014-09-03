<?php
namespace Psecio\Versionscan\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputOption;

class ScanCommand extends Command
{
    protected function configure()
    {
        $this->setName('scan')
            ->setDescription('Report back vulnerabilities for the current PHP version')
            ->setDefinition(array(
                new InputOption('php-version', 'php-version', InputOption::VALUE_OPTIONAL, 'PHP version to check'),
                new InputOption('fail-only', 'fail-only', InputOption::VALUE_NONE, 'Show only failures'),
                new InputOption('sort', 'sort', InputOption::VALUE_OPTIONAL, 'Sort Results By Column (cve, risk)')
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

        $scan = new \Psecio\Versionscan\Scan();
        $scan->execute($phpVersion);

        $output->writeLn('Executing against version: '.$scan->getVersion());

        $failedCount = 0;

        $table = $this->getApplication()->getHelperSet()->get('table');
        $table->setHeaders(array('Status', 'CVE ID', 'Risk', 'Summary'));

        $data = array();
        $column = 100;

        foreach ($scan->getChecks() as $check) {
            if ($failOnly !== null && $check->getResult() !== true) {
                continue;
            }

            if ($check->getResult() === true) {
                $status = '<fg=red>FAIL</fg=red>';
                $failedCount++;
            } else {
                $status = '<fg=green>PASS</fg=green>';
            }

            if ($output->isVerbose() === true) {
                $summary = trim($check->getSummary());
            } else {
                $summary = (strlen($check->getSummary()) > $column
                    ? substr($check->getSummary(), 0, $column-3) . '...' : $check->getSummary());
            }

            $data[] = array(
                $status,
                $check->getCveId(),
                $check->getThreat(),
                $summary,
            );
        }

        if ($sort !== false) {
            usort($data, function($row1, $row2) use ($sort) {
                $sort = strtolower($sort);

                if ($sort == 'cve') {
                    $r1 = str_replace(array('CVE', '-'), '', $row1[1]);
                    $r2 = str_replace(array('CVE', '-'), '', $row2[1]);

                    return ($r1 > $r2) ? -1 : 1;
                } elseif ($sort == 'risk') {
                    $r1 = (integer)$row1[2];
                    $r2 = (integer)$row2[2];

                    return ($r1 > $r2) ? -1 : 1;
                }
            });
        }

        $table->setRows($data);
        $table->render($output);

        $output->writeLn(
            "\nScan complete\n"
            .str_repeat('-', 20)."\n"
            ."Total checks: ".count($scan->getChecks())."\n"
            ."<fg=red>Failures: ".$failedCount."</fg=red>\n"
        );
    }
}

?>
