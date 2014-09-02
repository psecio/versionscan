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

        $scan = new \Psecio\Versionscan\Scan();
        $scan->execute($phpVersion);

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

            $summary = (strlen($check->getSummary()) > $column ? substr($check->getSummary(), 0, $column-3) . '...' : $check->getSummary());
            $data[] = array(
                $status,
                $check->getCveId(),
                $check->getThreat(),
                $summary,
            );
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
