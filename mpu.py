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

def MPU_Init():
    try:
        # Wake up the MPU6050 as it starts in sleep mode
        bus.write_byte_data(MPU6050_ADDRESS, PWR_MGMT_1, 0x00)
        time.sleep(0.1)
        # Set the sample rate to 1kHz by writing to the SMPLRT_DIV register
        bus.write_byte_data(MPU6050_ADDRESS, SMPLRT_DIV, 0x07)
        time.sleep(0.1)
        # Set the accelerometer configuration to +/- 2g (000)
        bus.write_byte_data(MPU6050_ADDRESS, CONFIG, 0x00)
        time.sleep(0.1)
        # Set the gyroscope configuration to +/- 250 degrees/sec (00)
        bus.write_byte_data(MPU6050_ADDRESS, GYRO_CONFIG, 0x00)
        time.sleep(0.1)
        # Enable interrupt
        bus.write_byte_data(MPU6050_ADDRESS, INT_ENABLE, 0x01)
        time.sleep(0.1)
        print("MPU6050 Initialized successfully.")
    except Exception as e:
        print(f"Failed to initialize MPU6050: {e}")

def read_raw_data(addr):
    try:
        # Accel and Gyro values are 16-bit
        high = bus.read_byte_data(MPU6050_ADDRESS, addr)
        low = bus.read_byte_data(MPU6050_ADDRESS, addr + 1)
        # Concatenate higher and lower values
        value = (high << 8) | low
        # Convert to signed value
        if value > 32768:
            value -= 65536
        return value
    except Exception as e:
        print(f"Failed to read raw data from address {addr}: {e}")
        return None

# Create an I2C bus object
bus = smbus2.SMBus(1)

# Initialize the MPU6050
MPU_Init()

print("Reading Data from MPU6050")

try:
    while True:
        # Read Accelerometer raw values
        acc_x = read_raw_data(ACCEL_XOUT_H)
        acc_y = read_raw_data(ACCEL_YOUT_H)
        acc_z = read_raw_data(ACCEL_ZOUT_H)

        # Read Gyroscope raw values
        gyro_x = read_raw_data(GYRO_XOUT_H)
        gyro_y = read_raw_data(GYRO_YOUT_H)
        gyro_z = read_raw_data(GYRO_ZOUT_H)

        if None not in (acc_x, acc_y, acc_z, gyro_x, gyro_y, gyro_z):
            # Full scale range +/- 2g for accelerometer and +/- 250 degrees/sec for gyroscope
            Ax = acc_x / 16384.0
            Ay = acc_y / 16384.0
            Az = acc_z / 16384.0

            Gx = gyro_x / 131.0
            Gy = gyro_y / 131.0
            Gz = gyro_z / 131.0

            print(f"Ax: {Ax:.2f} g Ay: {Ay:.2f} g Az: {Az:.2f} g Gx: {Gx:.2f} °/s Gy: {Gy:.2f} °/s Gz: {Gz:.2f} °/s")
        else:
            print("Error reading sensor data.")

        time.sleep(1)
except KeyboardInterrupt:
    print("\nTerminating the program.")
