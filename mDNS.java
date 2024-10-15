
// #region Imports
import java.io.IOException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.net.InetAddress;
import java.net.DatagramPacket;
import java.net.SocketException;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
// #endregion

public class mDNS {
  // #region Variables
  private static final String MDNS_ADDRESS = "224.0.0.251";
  private static final int MDNS_PORT = 5353;
  private static MulticastSocket socket = null;
  private static boolean scanning = false;
  // #endregion

  // #region Classes
  private static class RecordType {
    public static final int A = 1;
    public static final int NS = 2;
    public static final int CNAME = 5;
    public static final int PTR = 12;
    public static final int TXT = 16;
    public static final int AAAA = 28;
    public static final int SRV = 33;
    public static final int All = 255;

    public static String toName(int rType) {
      if (rType == RecordType.A) {
        return "A";
      } else if (rType == RecordType.NS) {
        return "NS";
      } else if (rType == RecordType.CNAME) {
        return "CNAME";
      } else if (rType == RecordType.PTR) {
        return "PTR";
      } else if (rType == RecordType.TXT) {
        return "TXT";
      } else if (rType == RecordType.AAAA) {
        return "AAAA";
      } else if (rType == RecordType.SRV) {
        return "SRV";
      } else if (rType == RecordType.All) {
        return "All";
      }
      return "Unknown";
    }
  }

  private static class Record {
    public String name;
    public int rType;
    public String rTypeName;
    public int ttl;
    public int port;
    public String data;

    public Record(String name, int rType, int ttl, int port, String data) {
      this.name = name;
      this.rType = rType;
      this.rTypeName = RecordType.toName(rType);
      this.ttl = ttl;
      this.port = port;
      this.data = data;
    }

    public void Log() {
      System.out.printf("Name: %s | rType: %s | ttl: %d | port: %d | data: %s\n", this.name, this.rTypeName, this.ttl,
          this.port, this.data);
    }
  }

  private static class DecodedName {
    public int consumed;
    public String s;
    public ArrayList<String> labels;

    public DecodedName(int consumed, String s, ArrayList<String> labels) {
      this.consumed = consumed;
      this.s = s;
      this.labels = labels;
    }
  }

  private static class Question {
    public String name;
    public int rType;

    public Question(String name, int rType) {
      this.name = name;
      this.rType = rType;
    }

    public void Log() {
      System.out.printf("Name: %s | rType: %s\n", this.name, this.rType);
    }
  }

  private static class Message {
    public int qr;
    public Question[] questions;
    public Record[] records;

    public Message(int qr, Question[] questions, Record[] records) {
      this.qr = qr;
      this.questions = questions;
      this.records = records;
    }
  }
  // #endregion

  // #region Helpers
  private static NetworkInterface findValidInterface() {
    try {

      for (NetworkInterface netInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
        if (netInterface.isUp() &&
            !netInterface.isLoopback() &&
            !netInterface.isVirtual() &&
            netInterface.getInetAddresses().hasMoreElements()) {
          return netInterface;
        }
      }
    } catch (SocketException e) {
      e.printStackTrace();
    }

    return null;
  }

  private static DecodedName DecodeName(byte[] buff, int offset) {
    int consumed = 0;
    boolean jumped = false;
    ArrayList<String> labels = new ArrayList<>();
    while (true) {
      if ((buff[offset] & 0xFF) == 0) {
        if (!jumped) {
          consumed++;
        }
        break;
      } else if ((buff[offset] & 0xC0) == 0xC0) {
        offset = (((buff[offset] & 0xFF) << 8) | (buff[offset + 1] & 0xFF)) - 0xC000;
        if (!jumped) {
          consumed += 2;
        }
        jumped = true;
      } else {
        int labelLength = buff[offset] & 0xFF;
        String label = new String(buff, offset + 1, labelLength);
        offset += 1 + labelLength;
        if (!jumped) {
          consumed += 1 + labelLength;
        }
        labels.add(label);
      }
    }
    String s = String.join(".", labels);
    return new DecodedName(consumed, s, labels);
  }

  private static Message decodeMsg(byte[] buff) {
    int qr = (buff[2] & 0xFF) >> 7;
    int offset = 12;
    Record[] records = new Record[0];
    Question[] questions = new Question[0];
    if (qr == 0) {
      int qCount = ((buff[4] & 0xFF) << 8) | (buff[5] & 0xFF);
      questions = new Question[qCount];
      System.out.printf("Received query with %d questions\n", qCount);

      for (int i = 0; i < qCount; i++) {
        DecodedName name = DecodeName(buff, offset);
        offset += name.consumed;
        int rType = ((buff[offset] & 0xFF) << 8) | (buff[offset + 1] & 0xFF);
        // int rClass = ((buff[offset + 2] & 0xFF) << 8) | (buff[offset + 3] & 0xFF);

        questions[i] = new Question(name.s, rType);
        questions[i].Log();
        offset += 4;
      }

    } else {
      int rCount = ((buff[6] & 0xFF) << 8) | (buff[7] & 0xFF);
      records = new Record[rCount];
      System.out.printf("Received response with %d answers\n", rCount);

      for (int i = 0; i < rCount; i++) {
        DecodedName name = DecodeName(buff, offset);
        offset += name.consumed;
        int rType = ((buff[offset] & 0xFF) << 8) | (buff[offset + 1] & 0xFF);
        // int rClass = ((buff[offset + 2] & 0xFF) << 8) | (buff[offset + 3] & 0xFF);
        String data = "";
        int port = -1;
        offset += 4;

        int ttl = ((buff[offset] & 0xFF) << 24) |
            ((buff[offset + 1] & 0xFF) << 16) |
            ((buff[offset + 2] & 0xFF) << 8) |
            (buff[offset + 3] & 0xFF);

        int dataLength = ((buff[offset + 4] & 0xFF) << 8) | (buff[offset + 5] & 0xFF);

        if (rType == RecordType.A) {
          String[] parts = new String[4];
          for (int y = 0; y < 4; y++) {
            parts[y] = Integer.toUnsignedString(buff[offset + 6 + y] & 0xFF);
          }
          data = String.join(".", parts);
        } else if (rType == RecordType.AAAA) {
          String[] parts = new String[dataLength];
          for (int y = 0; y < 16; y++) {
            parts[y] = Integer.toHexString(buff[offset + 6 + y] & 0xFF);
          }
          data = String.join(":", parts);
        } else if (rType == RecordType.NS) {

        } else if (rType == RecordType.CNAME || rType == RecordType.TXT || rType == RecordType.PTR) {
          data = DecodeName(buff, offset + 6).s;
        } else if (rType == RecordType.SRV) {
          port = ((buff[offset + 10] & 0xFF) << 8) | (buff[offset + 11] & 0xFF);
          data = DecodeName(buff, offset + 12).s;
        }

        Record record = new Record(name.s, rType, ttl, port, data);
        records[i] = record;

        record.Log();
        offset += 6 + dataLength;
      }
    }
    System.out.println();
    return new Message(qr, questions, records);

  }

  private static byte[] encodeQuery(Question[] questions) {
    byte[][] encodedQuestions = new byte[questions.length][];
    for (int i = 0; i < questions.length; i++) {
      String[] labels = questions[i].name.split("\\.");
      int encodeLen = 0;
      for (String label : labels) {
        encodeLen += 1 + label.length();
      }
      byte[] qBuff = new byte[encodeLen + 5];
      int offset = 0;
      for (String label : labels) {
        qBuff[offset] = (byte) (label.length() & 0xFF);
        byte[] labelBuff = label.getBytes();
        int x;
        for (offset += 1, x = 0; x < label.length(); offset++, x++) {
          qBuff[offset] = labelBuff[x];
        }
      }
      qBuff[offset] = 0x00;
      qBuff[offset + 1] = (byte) ((questions[i].rType & 0xFF) >> 8);
      qBuff[offset + 2] = (byte) (questions[i].rType & 0xFF);
      qBuff[offset + 3] = 0x00;
      qBuff[offset + 4] = 0x01;
      encodedQuestions[i] = qBuff;
    }

    int bufferLen = 12;
    for (byte[] encodedQuestion : encodedQuestions) {
      bufferLen += encodedQuestion.length;
    }

    byte[] buff = new byte[bufferLen];
    // id
    buff[0] = 0x00;
    buff[1] = 0x00;
    // flags
    buff[2] = 0x00;
    buff[3] = 0x00;
    // questions
    buff[4] = (byte) ((questions.length & 0xFF) >> 8);
    buff[5] = (byte) (questions.length & 0xFF);
    //
    buff[6] = 0x00;
    buff[7] = 0x00;
    buff[8] = 0x00;
    buff[9] = 0x00;
    buff[10] = 0x00;
    buff[11] = 0x00;

    int offset = 12;
    for (byte[] encodedQuestion : encodedQuestions) {
      for (int i = 0; i < encodedQuestion.length; i++) {
        buff[offset + i] = encodedQuestion[i];
      }
      offset += encodedQuestion.length;
    }
    return buff;
  }
  // #endregion

  private static boolean Init() {
    if (socket == null) {
      InetAddress group;
      NetworkInterface myInterface;
      try {
        group = InetAddress.getByName(MDNS_ADDRESS);
        myInterface = findValidInterface();
      } catch (UnknownHostException e) {
        e.printStackTrace();
        return false;
      }

      try {
        socket = new MulticastSocket(MDNS_PORT);
        socket.joinGroup(new InetSocketAddress(group, MDNS_PORT), myInterface);
      } catch (IOException e) {
        e.printStackTrace();
        return false;
      }
    }

    return true;
  }

  public static void Scan() {
    byte[] buff = new byte[10000];
    DatagramPacket packet = new DatagramPacket(buff, buff.length);

    while (true) {
      scanning = true;
      if (socket == null) {
        break;
      }

      try {
        socket.receive(packet);
      } catch (IOException e) {
        e.printStackTrace();
        continue;
      }
      decodeMsg(buff);
    }
    scanning = false;

  }

  public static void Start() {
    boolean success = Init();
    if (scanning || !success) {
      return;
    }

    Thread scanThread = new Thread(() -> Scan());
    scanThread.start();
  }

  public static void Stop() {
    if (socket != null) {
      socket.close();
      socket = null;
    }
  }

  public static boolean SendQuery(Question[] qs) {
    boolean success = Init();
    if (!success) {
      return false;
    }

    InetSocketAddress group;
    try {
      InetAddress mcastaddr = InetAddress.getByName(MDNS_ADDRESS);
      group = new InetSocketAddress(mcastaddr, MDNS_PORT);

    } catch (UnknownHostException e) {
      e.printStackTrace();
      return false;
    }

    byte[] buff = encodeQuery(qs);
    DatagramPacket packet = new DatagramPacket(buff, buff.length, group);
    try {
      socket.send(packet);
    } catch (IOException e) {
      e.printStackTrace();
      return false;
    }
    return true;
  }

  public static void main(String[] args) {
    Start();
    while (!scanning)
      ;
    boolean sent = SendQuery(new Question[] { new Question("_raop._tcp", 12) });
    System.out.printf("Sent success: %b\n", sent);
  }
}