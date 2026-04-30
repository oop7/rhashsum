import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/tauri";
import { open as openDialog, save } from '@tauri-apps/api/dialog';
import { open as openExternal } from '@tauri-apps/api/shell';
import { listen } from '@tauri-apps/api/event';
import { invoke as invokeTauri } from '@tauri-apps/api/tauri';
import { 
  ThemeProvider, 
  createTheme, 
  CssBaseline, 
  Container, 
  Box, 
  Tabs, 
  Tab, 
  Button, 
  TextField, 
  Checkbox, 
  FormControlLabel, 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow, 
  Paper, 
  Grid, 
  Menu, 
  MenuItem, 
  Typography, 
  IconButton,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Link,
} from "@mui/material";
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import Brightness4Icon from '@mui/icons-material/Brightness4';
import Brightness7Icon from '@mui/icons-material/Brightness7';

function App() {
  // Theme state with localStorage persistence
  const [isDarkMode, setIsDarkMode] = useState(() => {
    const savedTheme = localStorage.getItem('theme-mode');
    return savedTheme ? savedTheme === 'dark' : true; // Default to dark mode
  });

  // Save theme preference whenever it changes
  useEffect(() => {
    localStorage.setItem('theme-mode', isDarkMode ? 'dark' : 'light');
  }, [isDarkMode]);

  // Create theme with smooth transitions
  const theme = createTheme({
    palette: {
      mode: isDarkMode ? 'dark' : 'light',
    },
    transitions: {
      duration: {
        shortest: 150,
        shorter: 200,
        short: 250,
        standard: 300,
        complex: 375,
        enteringScreen: 225,
        leavingScreen: 195,
      },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            transition: 'background-color 0.3s ease, color 0.3s ease',
          },
        },
      },
    },
  });

  const [activeTab, setActiveTab] = useState(0);
  const [filePath, setFilePath] = useState("");
  const [folderPath, setFolderPath] = useState("");
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null); 
  const [checkingUpdate, setCheckingUpdate] = useState(false);

  // Dialog states
  const [aboutDialogOpen, setAboutDialogOpen] = useState(false);
  const [alertDialogOpen, setAlertDialogOpen] = useState(false);
  const [alertMessage, setAlertMessage] = useState("");
  const [alertTitle, setAlertTitle] = useState("");

  // Hash algorithm selection state with localStorage persistence
  const [selectedAlgorithms, setSelectedAlgorithms] = useState(() => {
    const saved = localStorage.getItem('hash-algorithms');
    return saved ? JSON.parse(saved) : {
      md5: true,
      sha1: false, 
      sha256: false,
      sha512: false,
      blake3: false,
      xxhash3: false
    };
  });

  // Save preferences whenever they change
  useEffect(() => {
    localStorage.setItem('hash-algorithms', JSON.stringify(selectedAlgorithms));
  }, [selectedAlgorithms]);

  const handleAlgorithmChange = (algorithm: string, checked: boolean) => {
    setSelectedAlgorithms((prev: { [key: string]: boolean }) => ({
      ...prev,
      [algorithm]: checked
    }));
  };

  // Helper function to show themed alerts
  const showAlert = (title: string, message: string) => {
    setAlertTitle(title);
    setAlertMessage(message);
    setAlertDialogOpen(true);
  };

  useEffect(() => {
    const unlisten = listen<string[]>('tauri://file-drop', (event: { payload: string[] }) => {
      if (event.payload.length > 0) {
        const droppedFile = event.payload[0];
        setActiveTab(0);
        
        // Force recalculation even if it's the same file by temporarily clearing path
        if (droppedFile === filePath) {
          // Same file dropped - force recalculation by temporarily clearing path then setting it
          setFilePath("");
          setTimeout(() => setFilePath(droppedFile), 10);
        } else {
          // Different file - normal flow
          setFilePath(droppedFile);
        }
      }
    });

    return () => {
      unlisten.then((f: () => void) => f());
    };
  }, [filePath]);

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  const handleMenuClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleCheckForUpdates = async () => {
    handleMenuClose();
    // show progress bar while we check
    setCheckingUpdate(true);
    try {
      const updateInfo = await invoke("check_for_updates");
      // If the updater returns an object when an update is available, treat that as update available.
      // If it returns null/undefined or an empty value, treat as up-to-date.
      if (!updateInfo) {
        showAlert('Update Check', 'Your app is up to date.');
      } else if (typeof updateInfo === 'object' && (updateInfo as any).version) {
        showAlert('Update Available', `Update available: ${(updateInfo as any).version}`);
      } else if (typeof updateInfo === 'string') {
        // If a string is returned, display a minimal message (no changelog)
        showAlert('Update Check', `Update check result: ${updateInfo}`);
      } else {
        showAlert('Update Check', 'Your app is up to date.');
      }
    } catch (error) {
      // Some updater implementations may throw when there's no update; treat as up-to-date.
      console.error('Update check failed', error);
      showAlert('Update Check', 'Your app is up to date.');
    } finally {
      setCheckingUpdate(false);
    }
  };

  const handleAbout = () => {
    handleMenuClose();
    setAboutDialogOpen(true);
  };

  const handleSponsor = async () => {
    handleMenuClose();
    try {
      await openExternal('https://github.com/sponsors/oop7');
    } catch (error) {
      showAlert('Sponsor', `Unable to open sponsor page: ${error}`);
    }
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container sx={{ py: 0, minHeight: '100vh' }}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexDirection: 'column' }}>
          <Box sx={{ width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Tabs value={activeTab} onChange={handleTabChange} aria-label="basic tabs example">
            <Tab label="Single File" />
            <Tab label="Folder Scan" />
            <Tab label="GPG Verify" />
          </Tabs>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <IconButton onClick={() => setIsDarkMode(!isDarkMode)} color="inherit">
              {isDarkMode ? <Brightness7Icon /> : <Brightness4Icon />}
            </IconButton>
            <Button
              aria-controls="help-menu"
              aria-haspopup="true"
              onClick={handleMenuClick}
              variant="contained"
            >
              Help
            </Button>
          </Box>
          </Box>
          {checkingUpdate && <LinearProgress sx={{ width: '100%' }} />}
          <Menu
            id="help-menu"
            anchorEl={anchorEl}
            keepMounted
            open={Boolean(anchorEl)}
            onClose={handleMenuClose}
          >
            <MenuItem onClick={handleCheckForUpdates}>Check for Updates</MenuItem>
            <MenuItem onClick={handleSponsor}>Sponsor</MenuItem>
            <MenuItem onClick={handleAbout}>About</MenuItem>
          </Menu>
        </Box>
        <TabPanel value={activeTab} index={0}>
          <SingleFileTab filePath={filePath} setFilePath={setFilePath} selectedAlgorithms={selectedAlgorithms} handleAlgorithmChange={handleAlgorithmChange} showAlert={showAlert} />
        </TabPanel>
        <TabPanel value={activeTab} index={1}>
          <FolderScanTab folderPath={folderPath} setFolderPath={setFolderPath} selectedAlgorithms={selectedAlgorithms} handleAlgorithmChange={handleAlgorithmChange} showAlert={showAlert} />
        </TabPanel>
        <TabPanel value={activeTab} index={2}>
          <GpgVerifyTab showAlert={showAlert} />
        </TabPanel>
      </Container>

      {/* About Dialog */}
      <Dialog open={aboutDialogOpen} onClose={() => setAboutDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ textAlign: 'center' }}>
          🔐 Rust Hash Sum
        </DialogTitle>
        <DialogContent>
          <Typography variant="h6" gutterBottom>
            🚀 High-Performance Hash Calculator
          </Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Built with Tauri + Rust + React
          </Typography>

          <Typography variant="h6" sx={{ mt: 2 }} gutterBottom>
            📋 Supported Algorithms:
          </Typography>
          <Typography variant="body2">
            • MD5, SHA-1, SHA-256, SHA-512<br/>
            • BLAKE3 (Ultra-fast, multithreaded)<br/>
            • XXHash3 (Extremely fast checksum)
          </Typography>

          <Typography variant="h6" sx={{ mt: 2 }} gutterBottom>
            ✨ Features:
          </Typography>
          <Typography variant="body2">
            • Optimized for large files (5GB+ support)<br/>
            • Multithreaded BLAKE3 + XXHash3 engines<br/>
            • Memory-mapped file access for streaming<br/>
            • Persistent algorithm & theme preferences<br/>
            • Single file & recursive folder hashing<br/>
            • Hash verification & exportable reports
          </Typography>

          <Typography variant="h6" sx={{ mt: 2 }} gutterBottom>
            💻 Technology Stack:
          </Typography>
          <Typography variant="body2">
            • Backend: Rust with the Tauri framework<br/>
            • Frontend: React with TypeScript<br/>
            • UI: Material-UI components<br/>
            • Performance: BLAKE3 acceleration + memory mapping
          </Typography>

          <Typography variant="h6" sx={{ mt: 2 }} gutterBottom>
            👥 Author & Source:
          </Typography>
          <Typography variant="body2">
            • Author: <Link href="https://github.com/oop7" target="_blank" rel="noopener">oop7</Link><br/>
            • Repository: <Link href="https://github.com/oop7/rhashsum" target="_blank" rel="noopener">github.com/oop7/rhashsum</Link><br/>
            • Sponsor: <Link href="https://github.com/sponsors/oop7" target="_blank" rel="noopener">github.com/sponsors/oop7</Link>
          </Typography>

          <Typography variant="body2" sx={{ mt: 2, fontStyle: 'italic' }}>
            🛠️ Crafted for maximum speed, reliability, and developer ergonomics
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAboutDialogOpen(false)} variant="contained">
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Alert Dialog */}
      <Dialog open={alertDialogOpen} onClose={() => setAlertDialogOpen(false)}>
        <DialogTitle>{alertTitle}</DialogTitle>
        <DialogContent>
          <Typography>{alertMessage}</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAlertDialogOpen(false)} variant="contained">
            OK
          </Button>
        </DialogActions>
      </Dialog>
    </ThemeProvider>
  );
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
      style={{ display: value === index ? 'block' : 'none' }}
    >
      <Box sx={{ p: 0 }}>
        {children}
      </Box>
    </div>
  );
}

interface SingleFileTabProps {
    filePath: string;
    setFilePath: (path: string) => void;
    selectedAlgorithms: { [key: string]: boolean };
    handleAlgorithmChange: (algorithm: string, checked: boolean) => void;
    showAlert: (title: string, message: string) => void;
}

interface GpgVerificationResult {
  valid_signature: boolean;
  fingerprint_match: boolean;
  signer: string | null;
  fingerprint: string | null;
  trust_level: string | null;
  status_lines: string[];
  message: string;
}

const SingleFileTab = ({ filePath, setFilePath, selectedAlgorithms, handleAlgorithmChange, showAlert }: SingleFileTabProps) => {
  const [md5, setMd5] = useState("");
  const [sha1, setSha1] = useState("");
  const [sha256, setSha256] = useState("");
  const [sha512, setSha512] = useState("");
  const [blake3, setBlake3] = useState("");
  const [xxhash3, setXxhash3] = useState("");
  const [expectedHash, setExpectedHash] = useState("");
  const [progress, setProgress] = useState<{ percent: number; bytes_read: number; total: number } | null>(null);
  const [isHashing, setIsHashing] = useState(false);
  const hashCacheRef = useRef<Record<string, Record<string, string>>>({});
  const validatedFileRef = useRef<string>("");

  // Clear hash results
  const clearHashes = () => {
    setMd5("");
    setSha1("");
    setSha256("");
    setSha512("");
    setBlake3("");
    setXxhash3("");
  };

  const applyHashResults = (results: Record<string, string>) => {
    setMd5(results.md5 || "");
    setSha1(results.sha1 || "");
    setSha256(results.sha256 || "");
    setSha512(results.sha512 || "");
    setBlake3(results.blake3 || "");
    setXxhash3(results.xxhash3 || "");
  };

  // Handle file selection: only set the path; calculation is handled by useEffect
  const handleFileSelect = async (path?: string) => {
    const selectedPath = path || await openDialog({ multiple: false });
    if (typeof selectedPath === 'string') {
      setFilePath(selectedPath);
    }
  };

  // Unified calculation: runs when file or algorithm selection changes
  useEffect(() => {
    const run = async () => {
      if (!filePath) return;
      const algorithms = Object.entries(selectedAlgorithms)
        .filter(([, v]) => v)
        .map(([k]) => k);
      if (algorithms.length === 0) return;

      const cacheForFile = hashCacheRef.current[filePath] || {};
      const missingAlgorithms = algorithms.filter((algorithm) => !cacheForFile[algorithm]);

      // Instantly render any cached values for this file.
      if (Object.keys(cacheForFile).length > 0) {
        applyHashResults(cacheForFile);
      } else {
        clearHashes();
      }

      // Nothing new to compute.
      if (missingAlgorithms.length === 0) {
        return;
      }

      setIsHashing(true);
      setProgress({ percent: 0, bytes_read: 0, total: 0 });

      try {
        // Validate the dropped/selected path is a file by calling a small Rust helper command.
        if (validatedFileRef.current !== filePath) {
          try {
            const isFile = await invokeTauri<boolean>('is_path_file', { path: filePath });
            if (!isFile) {
              showAlert('Invalid selection', 'You dropped a folder into Single File mode. Please drop a single file or switch to Folder Scan.');
              setIsHashing(false);
              setProgress(null);
              return;
            }
            validatedFileRef.current = filePath;
          } catch (e) {
            console.error('Failed to validate path via backend', e);
            showAlert('Error', 'Unable to access the selected path. Make sure the file exists and you have permission to read it.');
            setIsHashing(false);
            setProgress(null);
            return;
          }
        }

        const checksums = await invoke("calculate_checksums", { filePath, algorithms: missingAlgorithms });
        const results = checksums as Record<string, string>;

        const mergedResults = { ...cacheForFile, ...results };
        hashCacheRef.current[filePath] = mergedResults;
        applyHashResults(mergedResults);
      } catch (error) {
        console.error('Hash calculation failed:', error);
        if (error !== "Cancelled") {
          showAlert('Error', 'Hash calculation failed: ' + error);
        }
      } finally {
        setIsHashing(false);
        setProgress(null);
      }
    };

    run();
  }, [filePath, selectedAlgorithms]);

  // Progress event listener
  useEffect(() => {
    let unlisten: any;
    (async () => {
      unlisten = await listen('hash-progress', (event: any) => {
        const payload = event.payload as any;
        if (payload.file === filePath) {
          setProgress({ 
            percent: payload.percent || 0, 
            bytes_read: payload.bytes_read || 0, 
            total: payload.total || 0 
          });
        }
      });
    })();

    return () => {
      if (unlisten && typeof unlisten.then === 'function') {
        unlisten.then((f: any) => f());
      }
    };
  }, [filePath]);

  const handleSaveReport = async () => {
    if (!filePath) {
      showAlert('Save Report', 'Select a file before saving the report.');
      return;
    }

    const targetPath = await save({
      title: 'Save File Hash Report',
      defaultPath: 'hash-report.json',
      filters: [{ name: 'JSON', extensions: ['json'] }],
    });

    if (!targetPath || targetPath.length === 0) {
      return;
    }

    const reportData = {
      File: filePath,
      MD5: md5,
      SHA1: sha1,
      SHA256: sha256,
      SHA512: sha512,
      BLAKE3: blake3,
      XXHash3: xxhash3,
    };

    try {
      const jsonData = JSON.stringify(reportData, null, 2);
      await invoke('save_report', { filePath: targetPath, data: jsonData, format: 'json' });
      showAlert('Save Report', `Report saved to ${targetPath}`);
    } catch (error) {
      console.error('Failed to save report', error);
      showAlert('Error', `Failed to save report: ${error}`);
    }
  };

  const handleVerifyHash = async () => {
    if (!filePath || !expectedHash.trim()) {
      showAlert("Verification", "Please select a file and enter an expected hash.");
      return;
    }
    const calculatedHashes = {
      md5: md5,
      sha1: sha1,
      sha256: sha256,
      sha512: sha512,
    };
    const isMatch = await invoke("verify_hash", { expectedHash, calculatedHashes });
    if (isMatch) {
      showAlert("Verification", "The hash matches!");
    } else {
      showAlert("Verification", "The hash does not match.");
    }
  };


  const [copied, setCopied] = useState({ md5: false, sha1: false, sha256: false, sha512: false, blake3: false, xxhash3: false });

  const handleCopy = async (key: 'md5' | 'sha1' | 'sha256' | 'sha512' | 'blake3' | 'xxhash3', value: string) => {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    setCopied(prev => ({ ...prev, [key]: true }));
    setTimeout(() => setCopied(prev => ({ ...prev, [key]: false })), 2000);
  } catch (e) {
    console.error('Copy failed', e);
  }
  };

  return (
    <Box sx={{ p: 1 }}> 
      {/* File Selection Row */}
      <Grid container spacing={1} alignItems="center" sx={{ mb: 2 }}>
        <Grid item xs={10}>
          <TextField label="File" value={filePath} fullWidth size="small" InputProps={{ readOnly: true }} />
        </Grid>
        <Grid item xs={2}>
          <Button variant="contained" onClick={() => handleFileSelect()} fullWidth size="small" disabled={isHashing}>Browse</Button>
        </Grid>
      </Grid>

      {/* Algorithm Selection */}
      <Typography variant="subtitle2" sx={{ mb: 1 }}>Hash Algorithms:</Typography>
      <Grid container spacing={1} sx={{ mb: 2 }}>
        <Grid item xs={6}>
          <FormControlLabel 
            control={<Checkbox checked={selectedAlgorithms.md5} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('md5', checked)} size="small" />} 
            label="MD5" 
          />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel 
            control={<Checkbox checked={selectedAlgorithms.sha1} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha1', checked)} size="small" />} 
            label="SHA-1" 
          />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel 
            control={<Checkbox checked={selectedAlgorithms.sha256} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha256', checked)} size="small" />} 
            label="SHA-256" 
          />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel 
            control={<Checkbox checked={selectedAlgorithms.sha512} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha512', checked)} size="small" />} 
            label="SHA-512" 
          />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel 
            control={<Checkbox checked={selectedAlgorithms.blake3} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('blake3', checked)} size="small" />} 
            label="BLAKE3" 
          />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel 
            control={<Checkbox checked={selectedAlgorithms.xxhash3} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('xxhash3', checked)} size="small" />} 
            label="XXHash3" 
          />
        </Grid>
      </Grid>

      {/* Hash Results - Only show selected algorithms */}
      <Typography variant="subtitle2" sx={{ mb: 1 }}>Hash Results:</Typography>
      <Grid container spacing={1}>
        {selectedAlgorithms.md5 && (
          <>
            <Grid item xs={2}>
              <Typography variant="body2" sx={{ mt: 1 }}>MD5:</Typography>
            </Grid>
            <Grid item xs={9}>
              <TextField value={md5} fullWidth size="small" InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={1}>
              <IconButton color={copied.md5 ? 'success' : 'default'} onClick={() => handleCopy('md5', md5)} aria-label="copy md5" size="small">
                {copied.md5 ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Grid>
          </>
        )}

        {selectedAlgorithms.sha1 && (
          <>
            <Grid item xs={2}>
              <Typography variant="body2" sx={{ mt: 1 }}>SHA-1:</Typography>
            </Grid>
            <Grid item xs={9}>
              <TextField value={sha1} fullWidth size="small" InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={1}>
              <IconButton color={copied.sha1 ? 'success' : 'default'} onClick={() => handleCopy('sha1', sha1)} aria-label="copy sha1" size="small">
                {copied.sha1 ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Grid>
          </>
        )}

        {selectedAlgorithms.sha256 && (
          <>
            <Grid item xs={2}>
              <Typography variant="body2" sx={{ mt: 1 }}>SHA-256:</Typography>
            </Grid>
            <Grid item xs={9}>
              <TextField value={sha256} fullWidth size="small" InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={1}>
              <IconButton color={copied.sha256 ? 'success' : 'default'} onClick={() => handleCopy('sha256', sha256)} aria-label="copy sha256" size="small">
                {copied.sha256 ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Grid>
          </>
        )}

        {selectedAlgorithms.sha512 && (
          <>
            <Grid item xs={2}>
              <Typography variant="body2" sx={{ mt: 1 }}>SHA-512:</Typography>
            </Grid>
            <Grid item xs={9}>
              <TextField value={sha512} fullWidth size="small" InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={1}>
              <IconButton color={copied.sha512 ? 'success' : 'default'} onClick={() => handleCopy('sha512', sha512)} aria-label="copy sha512" size="small">
                {copied.sha512 ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Grid>
          </>
        )}

        {selectedAlgorithms.blake3 && (
          <>
            <Grid item xs={2}>
              <Typography variant="body2" sx={{ mt: 1 }}>BLAKE3:</Typography>
            </Grid>
            <Grid item xs={9}>
              <TextField value={blake3} fullWidth size="small" InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={1}>
              <IconButton color={copied.blake3 ? 'success' : 'default'} onClick={() => handleCopy('blake3', blake3)} aria-label="copy blake3" size="small">
                {copied.blake3 ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Grid>
          </>
        )}

        {selectedAlgorithms.xxhash3 && (
          <>
            <Grid item xs={2}>
              <Typography variant="body2" sx={{ mt: 1 }}>XXHash3:</Typography>
            </Grid>
            <Grid item xs={9}>
              <TextField value={xxhash3} fullWidth size="small" InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={1}>
              <IconButton color={copied.xxhash3 ? 'success' : 'default'} onClick={() => handleCopy('xxhash3', xxhash3)} aria-label="copy xxhash3" size="small">
                {copied.xxhash3 ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Grid>
          </>
        )}

        {progress && (
          <Grid item xs={12} sx={{ mt: 1, mb: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Box sx={{ flex: 1 }}>
                <LinearProgress variant="determinate" value={Math.min(Math.max(progress.percent, 0), 100)} />
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mt: 0.5 }}>
                  <Typography variant="caption">{`${Math.round(progress.percent)}%`}</Typography>
                  {progress.total > 0 && (
                    <Typography variant="caption">{`${(progress.bytes_read / (1024*1024)).toFixed(2)} MB / ${(progress.total / (1024*1024*1024)).toFixed(2)} GB`}</Typography>
                  )}
                </Box>
              </Box>
              <Box>
                <Button variant="outlined" color="error" size="small" onClick={async () => { await invoke('cancel_hashing'); setIsHashing(false); setProgress(null); }}>Cancel</Button>
              </Box>
            </Box>
          </Grid>
        )}
      </Grid>

      {/* Verify Section */}
      <Box sx={{ mt: 2 }}>
        <Typography variant="subtitle2">Verify Hash:</Typography>
        <TextField
          placeholder="Paste hash to verify"
          value={expectedHash}
          onChange={(event: React.ChangeEvent<HTMLInputElement>) => setExpectedHash(event.target.value)}
          fullWidth
          size="small"
          sx={{ mt: 1 }}
        />
        <Button variant="contained" onClick={handleVerifyHash} fullWidth sx={{ mt: 1 }} size="small" disabled={isHashing}>Verify</Button>
      </Box>

      <Button variant="contained" onClick={handleSaveReport} fullWidth sx={{ mt: 1 }} size="small">Save Report</Button>
    </Box>
  );
};

interface GpgVerifyTabProps {
  showAlert: (title: string, message: string) => void;
}

const GpgVerifyTab = ({ showAlert }: GpgVerifyTabProps) => {
  const [filePath, setFilePath] = useState("");
  const [signaturePath, setSignaturePath] = useState("");
  const [expectedFingerprint, setExpectedFingerprint] = useState("");
  const [gpgResult, setGpgResult] = useState<GpgVerificationResult | null>(null);
  const [isVerifyingGpg, setIsVerifyingGpg] = useState(false);

  const handleFileSelect = async () => {
    const selectedPath = await openDialog({ multiple: false });
    if (typeof selectedPath === 'string') {
      setFilePath(selectedPath);
    }
  };

  const handleSignatureSelect = async () => {
    const selectedPath = await openDialog({ multiple: false });
    if (typeof selectedPath === 'string') {
      setSignaturePath(selectedPath);
    }
  };

  const handleVerifyGpg = async () => {
    if (!filePath) {
      showAlert('GPG Verification', 'Select a file before verifying its signature.');
      return;
    }
    if (!signaturePath) {
      showAlert('GPG Verification', 'Select a detached signature file (for example .sig or .asc).');
      return;
    }

    setIsVerifyingGpg(true);
    setGpgResult(null);

    try {
      const result = await invoke<GpgVerificationResult>('verify_gpg_signature', {
        filePath,
        signaturePath,
        expectedFingerprint: expectedFingerprint.trim() || null,
      });
      setGpgResult(result);
    } catch (error) {
      console.error('GPG verification failed:', error);
      showAlert('GPG Verification', `GPG verification failed: ${error}`);
    } finally {
      setIsVerifyingGpg(false);
    }
  };

  return (
    <Box sx={{ p: 1 }}>
      <Grid container spacing={1} alignItems="center" sx={{ mb: 2 }}>
        <Grid item xs={10}>
          <TextField label="File" value={filePath} fullWidth size="small" InputProps={{ readOnly: true }} />
        </Grid>
        <Grid item xs={2}>
          <Button variant="contained" onClick={handleFileSelect} fullWidth size="small" disabled={isVerifyingGpg}>Browse</Button>
        </Grid>
      </Grid>

      <Typography variant="subtitle2">Detached Signature File:</Typography>
      <Grid container spacing={1} alignItems="center" sx={{ mt: 0.5 }}>
        <Grid item xs={10}>
          <TextField
            placeholder="Detached signature file (.sig, .asc)"
            value={signaturePath}
            fullWidth
            size="small"
            InputProps={{ readOnly: true }}
          />
        </Grid>
        <Grid item xs={2}>
          <Button variant="contained" onClick={handleSignatureSelect} fullWidth size="small" disabled={isVerifyingGpg}>Browse</Button>
        </Grid>
      </Grid>

      <TextField
        label="Expected signing key fingerprint (optional)"
        value={expectedFingerprint}
        onChange={(event: React.ChangeEvent<HTMLInputElement>) => setExpectedFingerprint(event.target.value)}
        fullWidth
        size="small"
        sx={{ mt: 2 }}
      />

      <Button
        variant="contained"
        onClick={handleVerifyGpg}
        fullWidth
        sx={{ mt: 2 }}
        size="small"
        disabled={isVerifyingGpg}
      >
        {isVerifyingGpg ? 'Verifying Signature...' : 'Verify GPG Signature'}
      </Button>

      {gpgResult && (
        <Box sx={{ mt: 2, p: 1, border: 1, borderColor: 'divider', borderRadius: 1 }}>
          <Typography variant="body2" color={gpgResult.valid_signature && gpgResult.fingerprint_match ? 'success.main' : 'error.main'}>
            {gpgResult.message}
          </Typography>
          <Typography variant="body2" sx={{ mt: 0.5 }}>Signature valid: {gpgResult.valid_signature ? 'Yes' : 'No'}</Typography>
          <Typography variant="body2">Fingerprint match: {gpgResult.fingerprint_match ? 'Yes' : 'No'}</Typography>
          {gpgResult.signer && <Typography variant="body2">Signer: {gpgResult.signer}</Typography>}
          {gpgResult.fingerprint && <Typography variant="body2">Fingerprint: {gpgResult.fingerprint}</Typography>}
          {gpgResult.trust_level && <Typography variant="body2">Trust level: {gpgResult.trust_level}</Typography>}
        </Box>
      )}
    </Box>
  );
};

interface FolderScanTabProps {
    folderPath: string;
    setFolderPath: (path: string) => void;
    selectedAlgorithms: { [key: string]: boolean };
    handleAlgorithmChange: (algorithm: string, checked: boolean) => void;
    showAlert: (title: string, message: string) => void;
}

const FolderScanTab = ({ folderPath, setFolderPath, selectedAlgorithms, handleAlgorithmChange, showAlert }: FolderScanTabProps) => {
  const [files, setFiles] = useState<any[]>([]);
  const [includeSubfolders, setIncludeSubfolders] = useState(true);
  const [includeHidden, setIncludeHidden] = useState(false);
  const [isScanning, setIsScanning] = useState(false);

  const handleFolderSelect = async () => {
    const selected = await openDialog({
      directory: true,
      multiple: false,
    });
    if (typeof selected === 'string') {
      setFolderPath(selected);
    }
  };

  const handleScan = async () => {
    // Get only selected algorithms for folder scan
    const algorithms = Object.keys(selectedAlgorithms).filter(key => selectedAlgorithms[key]);
    
    if (algorithms.length === 0) {
      showAlert('Error', 'Please select at least one hash algorithm');
      return;
    }
    
    setIsScanning(true);
    setFiles([]);
    try {
      const scannedFiles = await invoke("scan_folder", { 
        folderPath, 
        includeSubfolders, 
        includeHidden,
        algorithms 
      });
      setFiles(scannedFiles as any[]);
    } catch (e) {
      if (e !== "Cancelled") showAlert('Error', `Folder scan failed: ${e}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSaveReport = async () => {
    if (!files.length) {
      showAlert('Save Folder Results', 'Scan a folder before saving results.');
      return;
    }

    const targetPath = await save({
      title: 'Save Folder Hash Results',
      defaultPath: 'folder-hash-results.json',
      filters: [{ name: 'JSON', extensions: ['json'] }],
    });

    if (!targetPath || targetPath.length === 0) {
      return;
    }

    try {
      const jsonData = JSON.stringify(files, null, 2);
      await invoke('save_report', { filePath: targetPath, data: jsonData, format: 'json' });
      showAlert('Save Folder Results', `Results saved to ${targetPath}`);
    } catch (error) {
      console.error('Failed to save folder results', error);
      showAlert('Error', `Failed to save folder results: ${error}`);
    }
  };

  return (
    <Box sx={{ p: 2 }}> 
        <Grid container spacing={2} alignItems="center">
            <Grid item xs={10}>
                <TextField label="Folder" value={folderPath} fullWidth InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={2}>
                <Button variant="contained" onClick={handleFolderSelect} fullWidth>Browse</Button>
            </Grid>
        </Grid>

        <Box sx={{ mt: 2 }}>
            <Typography variant="h6" sx={{ mb: 1 }}>Algorithm Selection:</Typography>
            <Grid container spacing={1}>
              <Grid item xs={4}>
                <FormControlLabel 
                  control={<Checkbox checked={selectedAlgorithms.md5} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('md5', checked)} size="small" />} 
                  label="MD5" 
                />
              </Grid>
              <Grid item xs={4}>
                <FormControlLabel 
                  control={<Checkbox checked={selectedAlgorithms.sha1} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha1', checked)} size="small" />} 
                  label="SHA-1" 
                />
              </Grid>
              <Grid item xs={4}>
                <FormControlLabel 
                  control={<Checkbox checked={selectedAlgorithms.sha256} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha256', checked)} size="small" />} 
                  label="SHA-256" 
                />
              </Grid>
              <Grid item xs={4}>
                <FormControlLabel 
                  control={<Checkbox checked={selectedAlgorithms.sha512} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha512', checked)} size="small" />} 
                  label="SHA-512" 
                />
              </Grid>
              <Grid item xs={4}>
                <FormControlLabel 
                  control={<Checkbox checked={selectedAlgorithms.blake3} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('blake3', checked)} size="small" />} 
                  label="BLAKE3" 
                />
              </Grid>
              <Grid item xs={4}>
                <FormControlLabel 
                  control={<Checkbox checked={selectedAlgorithms.xxhash3} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('xxhash3', checked)} size="small" />} 
                  label="XXHash3" 
                />
              </Grid>
            </Grid>
            <FormControlLabel control={<Checkbox checked={includeSubfolders} onChange={() => setIncludeSubfolders(!includeSubfolders)} />} label="Include Subfolders" />
            <FormControlLabel control={<Checkbox checked={includeHidden} onChange={() => setIncludeHidden(!includeHidden)} />} label="Include Hidden Files" />
        </Box>

        <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
          <Button variant="contained" onClick={handleScan} fullWidth disabled={isScanning}>Scan Folder</Button>
          {isScanning && (
            <Button variant="outlined" color="error" onClick={() => invoke('cancel_hashing')}>Cancel</Button>
          )}
        </Box>
        {isScanning && <LinearProgress sx={{ mt: 2 }} />}

        <TableContainer component={Paper} sx={{ mt: 2 }}>
            <Table>
                <TableHead>
                    <TableRow>
                        <TableCell>File Name</TableCell>
                        <TableCell>Path</TableCell>
                        {selectedAlgorithms.md5 && <TableCell>MD5</TableCell>}
                        {selectedAlgorithms.sha1 && <TableCell>SHA-1</TableCell>}
                        {selectedAlgorithms.sha256 && <TableCell>SHA-256</TableCell>}
                        {selectedAlgorithms.sha512 && <TableCell>SHA-512</TableCell>}
                        {selectedAlgorithms.blake3 && <TableCell>BLAKE3</TableCell>}
                        {selectedAlgorithms.xxhash3 && <TableCell>XXHash3</TableCell>}
                    </TableRow>
                </TableHead>
                <TableBody>
                    {files.map((file, index) => (
                        <TableRow key={index}>
                            <TableCell>{file.name}</TableCell>
                            <TableCell>{file.path}</TableCell>
                            {selectedAlgorithms.md5 && <TableCell>{file.md5 || ''}</TableCell>}
                            {selectedAlgorithms.sha1 && <TableCell>{file.sha1 || ''}</TableCell>}
                            {selectedAlgorithms.sha256 && <TableCell>{file.sha256 || ''}</TableCell>}
                            {selectedAlgorithms.sha512 && <TableCell>{file.sha512 || ''}</TableCell>}
                            {selectedAlgorithms.blake3 && <TableCell>{file.blake3 || ''}</TableCell>}
                            {selectedAlgorithms.xxhash3 && <TableCell>{file.xxhash3 || ''}</TableCell>}
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </TableContainer>
        <Button variant="contained" onClick={handleSaveReport} fullWidth sx={{ mt: 2 }}>Save Folder Results</Button>
    </Box>
  );
};

export default App;
