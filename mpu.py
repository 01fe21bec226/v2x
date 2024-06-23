import smbus2
import time

# MPU6050 Registers and their Addresses
PWR_MGMT_1 = 0x6B
SMPLRT_DIV = 0x19
CONFIG = 0x1A
GYRO_CONFIG = 0x1B
INT_ENABLE = 0x38
ACCEL_XOUT_H = 0x3B
ACCEL_YOUT_H = 0x3D
ACCEL_ZOUT_H = 0x3F
GYRO_XOUT_H = 0x43
GYRO_YOUT_H = 0x45
GYRO_ZOUT_H = 0x47

# I2C address of the MPU6050
MPU6050_ADDRESS = 0x68

class MPU6050:
    def __init__(self):
        self.bus = smbus2.SMBus(1)
        self.MPU_Init()

    def MPU_Init(self):
        try:
            # Wake up the MPU6050 as it starts in sleep mode
            self.bus.write_byte_data(MPU6050_ADDRESS, PWR_MGMT_1, 0x00)
            time.sleep(0.1)
            # Set the sample rate to 1kHz by writing to the SMPLRT_DIV register
            self.bus.write_byte_data(MPU6050_ADDRESS, SMPLRT_DIV, 0x07)
            time.sleep(0.1)
            # Set the accelerometer configuration to +/- 2g (000)
            self.bus.write_byte_data(MPU6050_ADDRESS, CONFIG, 0x00)
            time.sleep(0.1)
            # Set the gyroscope configuration to +/- 250 degrees/sec (00)
            self.bus.write_byte_data(MPU6050_ADDRESS, GYRO_CONFIG, 0x00)
            time.sleep(0.1)
            # Enable interrupt
            self.bus.write_byte_data(MPU6050_ADDRESS, INT_ENABLE, 0x01)
            time.sleep(0.1)
            print("MPU6050 Initialized successfully.")
        except Exception as e:
            print(f"Failed to initialize MPU6050: {e}")

    def read_raw_data(self, addr):
        try:
            # Accel and Gyro values are 16-bit
            high = self.bus.read_byte_data(MPU6050_ADDRESS, addr)
            low = self.bus.read_byte_data(MPU6050_ADDRESS, addr + 1)
            # Concatenate higher and lower values
            value = (high << 8) | low
            # Convert to signed value
            if value > 32768:
                value -= 65536
            return value
        except Exception as e:
            print(f"Failed to read raw data from address {addr}: {e}")
            return None

    @staticmethod
    def read_mpu():
        try:
            bus = smbus2.SMBus(1)

            # Read Accelerometer raw values
            acc_x = MPU6050.read_raw_data(bus, ACCEL_XOUT_H)
            acc_y = MPU6050.read_raw_data(bus, ACCEL_YOUT_H)
            acc_z = MPU6050.read_raw_data(bus, ACCEL_ZOUT_H)

            # Read Gyroscope raw values
            gyro_x = MPU6050.read_raw_data(bus, GYRO_XOUT_H)
            gyro_y = MPU6050.read_raw_data(bus, GYRO_YOUT_H)
            gyro_z = MPU6050.read_raw_data(bus, GYRO_ZOUT_H)

            if None not in (acc_x, acc_y, acc_z, gyro_x, gyro_y, gyro_z):
                # Full scale range +/- 2g for accelerometer and +/- 250 degrees/sec for gyroscope
                Ax = acc_x / 16384.0
                Ay = acc_y / 16384.0
                Az = acc_z / 16384.0

                Gx = gyro_x / 131.0
                Gy = gyro_y / 131.0
                Gz = gyro_z / 131.0

                return Ax, Ay, Az, Gx, Gy, Gz
            else:
                print("Error reading sensor data.")
                return None
        except Exception as e:
            print(f"Failed to read MPU6050 data: {e}")
            return None
