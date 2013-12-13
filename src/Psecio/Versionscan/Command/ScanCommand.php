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
     * @throws \Psecio\Iniscan\Exceptions\FormatNotFoundException
     * @throws \Exception
     * @return null
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $output->writeLn('Running scan!');
    }
}

?>
