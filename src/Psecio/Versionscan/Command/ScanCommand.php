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

        $output->writeLn(str_repeat('-', 50));
        $output->writeLn(
            str_pad('Status', 15, ' ').' | '
            . str_pad('CVE ID', 20, ' ')
            .'| Summary'
        );
        $output->writeLn(str_repeat('-', 50));

        $failedCount = 0;
        foreach ($scan->getChecks() as $check) {
            if ($failOnly !== null && $check->getResult() !== true) {
                continue;
            }

            if ($check->getResult() === true) {
                $status = 'FAIL';
                $color = 'red';
                $failedCount++;
            } else {
                $status = 'PASS';
                $color = 'green';
            }
            $output->writeLn(
                '<fg='.$color.'>'
                .str_pad($status, 15, ' ').' | '
                .str_pad($check->getCveId(), 20, ' ').'| '.$check->getSummary()
                .'</fg='.$color.'>'
            );
        }

        $output->writeLn(
            "\nScan complete\n"
            .str_repeat('-', 20)."\n"
            ."Total checks: ".count($scan->getChecks())."\n"
            ."<fg=red>Failures: ".$failedCount."</fg=red>\n"
        );
    }
}

?>
