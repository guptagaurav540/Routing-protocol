-- phpMyAdmin SQL Dump
-- version 5.1.0
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Generation Time: Jun 18, 2021 at 02:36 PM
-- Server version: 10.4.18-MariaDB
-- PHP Version: 8.0.3

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `SDN`
--

-- --------------------------------------------------------

--
-- Table structure for table `DELAY_TABLE`
--

CREATE TABLE `DELAY_TABLE` (
  `id` varchar(20) DEFAULT NULL,
  `delay` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `DELAY_TABLE`
--

INSERT INTO `DELAY_TABLE` (`id`, `delay`) VALUES
('switch5', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `HostConnection`
--

CREATE TABLE `HostConnection` (
  `switch` varchar(50) DEFAULT NULL,
  `ip` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `HostConnection`
--

INSERT INTO `HostConnection` (`switch`, `ip`) VALUES
('1', '10.0.0.1'),
('1', '10.0.0.2'),
('1', '10.0.0.3'),
('2', '10.0.0.4'),
('2', '10.0.0.5'),
('3', '10.0.0.6'),
('3', '10.0.0.7'),
('4', '10.0.0.8'),
('5', '10.0.0.9'),
('6', '10.0.0.10'),
('6', '10.0.0.11'),
('7', '10.0.0.12'),
('8', '10.0.0.13'),
('9', '10.0.0.14'),
('9', '10.0.0.15');

-- --------------------------------------------------------

--
-- Table structure for table `topotable`
--

CREATE TABLE `topotable` (
  `s1` varchar(20) DEFAULT NULL,
  `s1_p` varchar(20) DEFAULT NULL,
  `s2` varchar(20) DEFAULT NULL,
  `s2_p` varchar(20) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
